import os
import time
import base64
import requests

from flask import abort, Flask, render_template, request, redirect, jsonify
from datetime import date, datetime, timezone
from email.mime.text import MIMEText

from supabase import create_client, Client

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleRequest
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
import google.auth.transport.requests as grequests

  # saves & encrypts creds to Supabase
from fimap import send_email_smtp, fetch_emails_imap

from flask_cors import CORS  

from cryptography.fernet import Fernet

# bring in your Blueprints
from transaction_autopilot import bp as autopilot_bp
from public import public_bp

# ── single Flask app & blueprint registration ──
app = Flask(__name__, template_folder="templates")
CORS(app, resources={r"/connect-smtp": {"origins": "https://replyzeai.vercel.app"}})  # ← add this
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret")
#--------------------------------------------------------------
@app.route("/signin")
def signin():
    user_id = request.args.get("user_id", "")
    return render_template("signin.html", user_id=user_id)
#--------------------------------------------------------------
app.register_blueprint(autopilot_bp, url_prefix="/autopilot")
app.register_blueprint(public_bp)

# --- Supabase setup ---
SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_ANON_KEY = os.environ["SUPABASE_ANON_KEY"]
SUPABASE_SERVICE_ROLE_KEY = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
SUPABASE_SERVICE: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
# Edge Function base URL *without* trailing slash or endpoint
EDGE_BASE_URL = os.environ.get("EDGE_BASE_URL", "").rstrip("/")
ENCRYPTION_KEY = os.environ["ENCRYPTION_KEY"].encode()  # 32-url-safe-base64 bytes
fernet = Fernet(ENCRYPTION_KEY)
# Retry configuration for calling the Edge Function
MAX_RETRIES = 5
RETRY_BACKOFF_BASE = 2

#----------------------------------------------------------------------------
def get_smtp_creds(user_id: str):
    """Return decrypted (email, app_password) or (None, None)."""
    resp = supabase.from_("profiles").select("smtp_email, smtp_password").eq("id", user_id).single().execute()
    if resp.error or not resp.data:
        return None, None
    enc_pwd = resp.data["smtp_password"].encode()
    try:
        pwd = fernet.decrypt(enc_pwd).decode()
    except Exception:
        return None, None
    return resp.data["smtp_email"], pwd

# ---------------------------------------------------------------------------
def call_edge(endpoint_path: str, payload: dict) -> bool:
    url = f"{EDGE_BASE_URL}{endpoint_path}"
    app.logger.info(f"🔗 call_edge → URL: {url}")
    app.logger.info(f"🔗 call_edge → Payload: {payload}")

    headers = {
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "apikey":        SUPABASE_SERVICE_ROLE_KEY,
        "Content-Type":  "application/json"
    }

    for attempt in range(MAX_RETRIES):
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=120)
            app.logger.info(f"↩️  Response [{resp.status_code}]: {resp.text}")

            if resp.status_code == 200:
                return True
            elif resp.status_code == 429:
                wait = RETRY_BACKOFF_BASE ** attempt
                app.logger.warning(f"[{endpoint_path}] Rate‐limited, retry {attempt+1}/{MAX_RETRIES} after {wait}s")
                time.sleep(wait)
                continue
            else:
                app.logger.error(f"[{endpoint_path}] Failed ({resp.status_code}): {resp.text}")
                return False
        except requests.RequestException as e:
            wait = RETRY_BACKOFF_BASE ** attempt
            app.logger.error(f"[{endpoint_path}] Exception: {e}, retrying in {wait}s")
            time.sleep(wait)
    app.logger.error(f"[{endpoint_path}] Exceeded max retries.")
    return False

# ── Routes ──

from flask import url_for

@app.route("/")
def home():
    """
    Just redirect to /dashboard, passing along user_id if any.
    """
    user_id = request.args.get("user_id", "")
    # Redirect to /dashboard?user_id=<...> (blank if none)
    return redirect(f"/dashboard?user_id={user_id}")



@app.route("/dashboard")
def dashboard():
    user_id = request.args.get("user_id", "").strip()

    # --- GUEST DEFAULTS ---
    name            = "Guest"
    ai_enabled      = False
    generate_leases = False
    emails_sent     = 0
    time_saved      = 0
    show_reconnect  = False
    revenue         = 0
    revenue_change  = 0

    if user_id:
        # 1) Load profile
        try:
            resp = (supabase.table("profiles")
                            .select("full_name, ai_enabled, generate_leases")
                            .eq("id", user_id)
                            .single()
                            .execute())
            if resp.data:
                name            = resp.data["full_name"]
                ai_enabled      = resp.data["ai_enabled"]
                generate_leases = resp.data["generate_leases"]
        except Exception:
            app.logger.warning(f"dashboard: failed to load profile for {user_id}")

        # 2) Count today's emails
        try:
            today     = date.today().isoformat()
            rows      = (supabase.table("emails")
                                .select("sent_at")
                                .eq("user_id", user_id)
                                .eq("status", "sent")
                                .execute()
                                .data or [])
            emails_sent = sum(1 for e in rows if e.get("sent_at", "").startswith(today))
            time_saved  = emails_sent * 5.5
        except Exception:
            app.logger.warning(f"dashboard: failed to count emails for {user_id}")

        # 3) Gmail reconnect flag
        try:
            toks = (supabase.table("gmail_tokens")
                           .select("credentials")
                           .eq("user_id", user_id)
                           .execute()
                           .data or [])
            if toks:
                cd = toks[0]["credentials"]
                creds = Credentials(
                    token=cd["token"],
                    refresh_token=cd["refresh_token"],
                    token_uri=cd["token_uri"],
                    client_id=cd["client_id"],
                    client_secret=cd["client_secret"],
                    scopes=cd["scopes"],
                )
                show_reconnect = bool(creds.expired)
        except Exception:
            app.logger.warning(f"dashboard: failed to check Gmail token for {user_id}")

        # 4) (Optional) set revenue & change if you ever have real data
        # revenue = your_calc()
        # revenue_change = your_calc_change()

    # Render with safe, numeric defaults
    return render_template(
        "dashboard.html",
        user_id=user_id,
        name=name,
        ai_enabled=ai_enabled,
        generate_leases=generate_leases,
        emails_sent=emails_sent,
        time_saved=time_saved,
        show_reconnect=show_reconnect,
        revenue=revenue,
        revenue_change=revenue_change
    )

@app.route("/dashboard/new_transaction")
def dashboard_new_transaction():
    user_id = request.args.get("user_id") or abort(401)
    return render_template("partials/new_transaction.html", user_id=user_id)

@app.route("/dashboard/analytics")
def dashboard_analytics():
    user_id = _require_user()
    return render_template("partials/analytics.html", user_id=user_id)

@app.route("/dashboard/users")
def dashboard_users():
    user_id = _require_user()
    users = supabase.table("profiles").select("id, full_name, email").execute().data or []
    return render_template("partials/users.html", users=users)

@app.route("/dashboard/billing")
def dashboard_billing():
    user_id = _require_user()
    return render_template("partials/billing.html", user_id=user_id)

@app.route("/dashboard/settings", methods=["GET", "POST"])
def dashboard_settings():
    user_id = _require_user()

    # ─── Handle Profile POST ────────────────────────────────
    if request.method == "POST":
        section = request.form.get("section")
        if section == "profile":
            new_display_name = request.form.get("display_name", "").strip()
            new_signature = request.form.get("signature", "").strip()
            supabase.table("profiles").update({
                "display_name": new_display_name,
                "signature": new_signature
            }).eq("id", user_id).execute()

    # ─── Fetch profile & flags ──────────────────────────────
    profile_resp = supabase.table("profiles") \
                           .select("display_name, signature, ai_enabled, smtp_email") \
                           .eq("id", user_id) \
                           .single() \
                           .execute()
    
    profile = profile_resp.data or {
        "display_name": "",
        "signature": "",
        "ai_enabled": False,
        "smtp_email": None
    }

    # ▶ Determine whether the saved Gmail creds are expired
    show_reconnect = False
    try:
        toks = supabase.table("gmail_tokens") \
                       .select("credentials") \
                       .eq("user_id", user_id) \
                       .single() \
                       .execute().data
        if toks:
            creds_payload = toks["credentials"]
            creds = Credentials(
                token=creds_payload["token"],
                refresh_token=creds_payload["refresh_token"],
                token_uri=creds_payload["token_uri"],
                client_id=creds_payload["client_id"],
                client_secret=creds_payload["client_secret"],
                scopes=creds_payload["scopes"],
            )
            show_reconnect = creds.expired
    except Exception:
        app.logger.warning(f"settings: could not check Gmail token for {user_id}")

    # ▶ Render template
    return render_template(
        "partials/settings.html",
        profile=profile,
        user_id=user_id,
        show_reconnect=show_reconnect
    )
# New routes for SMTP management
@app.route("/connect_smtp_form", methods=["GET"])
def connect_smtp_form():
    user_id = request.args.get("user_id")
    return render_template("partials/connect_smtp_form.html", user_id=user_id)

@app.route("/disconnect_smtp", methods=["POST"])
def disconnect_smtp():
    user_id = request.form.get("user_id")
    supabase.table("profiles").update({
        "smtp_email": None,
        "smtp_enc_password": None,
        "smtp_host": None,
        "imap_host": None
    }).eq("id", user_id).execute()
    return redirect(f"/dashboard/settings?user_id={user_id}")

@app.route("/dashboard/home")
def dashboard_home():
    user_id = request.args.get("user_id")
    if not user_id:
        return "Missing user_id", 401

    # (Same logic as /dashboard for HTMX partial)
    profile_resp = (
        supabase.table("profiles")
                .select("full_name, ai_enabled, email, generate_leases")
                .eq("id", user_id)
                .single()
                .execute()
    )
    if profile_resp.data is None:
        return "Profile query error", 500

    profile         = profile_resp.data
    full_name       = profile.get("full_name", "")
    ai_enabled      = profile.get("ai_enabled", True)
    generate_leases = profile.get("generate_leases", False)

    today     = date.today().isoformat()
    sent_rows = (
        supabase.table("emails")
                .select("sent_at")
                .eq("user_id", user_id)
                .eq("status", "sent")
                .execute()
                .data
        or []
    )
    emails_sent_today = sum(1 for e in sent_rows if e.get("sent_at", "").startswith(today))
    time_saved        = emails_sent_today * 5.5

    token_rows = (
        supabase.table("gmail_tokens")
                .select("credentials")
                .eq("user_id", user_id)
                .execute()
                .data
        or []
    )
    show_reconnect = True
    if token_rows:
        creds_data = token_rows[0]["credentials"]
        try:
            creds = Credentials(
                token=creds_data["token"],
                refresh_token=creds_data["refresh_token"],
                token_uri=creds_data["token_uri"],
                client_id=creds_data["client_id"],
                client_secret=creds_data["client_secret"],
                scopes=creds_data["scopes"],
            )
            show_reconnect = creds.expired
        except Exception:
            pass

    return render_template(
        "partials/home.html",
        name=full_name,
        user_id=user_id,
        emails_sent=emails_sent_today,
        time_saved=time_saved,
        ai_enabled=ai_enabled,
        show_reconnect=show_reconnect,
        generate_leases=generate_leases,
    )
#----------------------------------------------------------------------
@app.route("/connect-smtp", methods=["POST"])
def route_connect_smtp():
    try:
        data = request.get_json(force=True)
        # pull out all five required fields
        user_id      = data.get("user_id")
        smtp_email   = data.get("smtp_email")
        smtp_password= data.get("smtp_password")
        smtp_host    = data.get("smtp_host")
        imap_host    = data.get("imap_host")

        # validate
        missing = [k for k in ("user_id","smtp_email","smtp_password","smtp_host","imap_host") if not data.get(k)]
        if missing:
            return jsonify({
                "status": "error",
                "message": f"Missing fields: {', '.join(missing)}"
            }), 400

        # encrypt & upsert
        token = fernet.encrypt(smtp_password.encode()).decode()
        resp = supabase.table("profiles").upsert({
            "id":                user_id,
            "smtp_email":        smtp_email,
            "smtp_enc_password": token,
            "smtp_folder":       "INBOX"
        }, on_conflict="id").execute()

        # **THIS** is the fix — supabase-py’s APIResponse has no `.error`
        if not resp or getattr(resp, "status_code", 0) >= 400:
            # pull any returned text out for debugging
            err = getattr(resp, "text", repr(resp))
            raise Exception(f"Supabase upsert failed: {err}")

        return jsonify({"status": "ok"}), 200

    except Exception as e:
        app.logger.error("connect-smtp error", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500



#------------------------------------------ 


#------------------------------------------
@app.route("/send", methods=["POST"])
def send_email():
    data = request.get_json()
    user_id = data["user_id"]
    to = data["to"]
    subject = data["subject"]
    body = data["body"]

    smtp_email, app_password = get_smtp_creds(user_id)
    if smtp_email and app_password:
        # Use SMTP fallback
        send_email_smtp(smtp_email, app_password, to, subject, body)
        return jsonify({"method": "smtp", "status": "sent"}), 200

    # else: your existing Gmail API flow
    return send_via_gmail_api(data)

@app.route("/fetch", methods=["GET"])
def fetch_mail():
    user_id = request.args.get("user_id")
    smtp_email, app_password = get_smtp_creds(user_id)
    if smtp_email and app_password:
        messages = fetch_emails_imap(smtp_email, app_password)
        return jsonify({"method": "imap", "messages": messages}), 200

    # else: your existing Gmail-API‐based fetch
    return fetch_via_gmail_api(user_id)

#-----------------------------------------------------------------------
@app.route("/connect_gmail")
def connect_gmail():
    """
    Initiates Gmail OAuth flow.
    """
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": os.environ["GOOGLE_CLIENT_ID"],
                "client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [os.environ["REDIRECT_URI"]]
            }
        },
        scopes=[
            "https://www.googleapis.com/auth/gmail.send",
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/gmail.compose",
            "openid"
        ]
    )
    flow.redirect_uri = os.environ["REDIRECT_URI"]
    authorization_url, _ = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent"
    )
    return redirect(authorization_url)

@app.route("/oauth2callback")
def oauth2callback():
    """
    Handles OAuth2 callback from Google.
    """
    try:
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": os.environ["GOOGLE_CLIENT_ID"],
                    "client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [os.environ["REDIRECT_URI"]]
                }
            },
            scopes=[
                "https://www.googleapis.com/auth/gmail.send",
                "https://www.googleapis.com/auth/gmail.readonly",
                "https://www.googleapis.com/auth/userinfo.email",
                "https://www.googleapis.com/auth/gmail.compose",
                "openid"
            ]
        )
        flow.redirect_uri = os.environ["REDIRECT_URI"]
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials

        id_info = id_token.verify_oauth2_token(
            credentials.id_token,
            grequests.Request(),
            os.environ["GOOGLE_CLIENT_ID"]
        )
        email = id_info.get("email")
        full_name = id_info.get("name") or email.split("@")[0]

        if not email:
            raise ValueError("No email found in Google ID token")

        # Find or create Auth user in Supabase
        auth_url = f"{SUPABASE_URL}/auth/v1/admin/users"
        headers = {
            "apikey": SUPABASE_SERVICE_ROLE_KEY,
            "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}"
        }
        resp = requests.get(auth_url, headers=headers, params={"email": email})
        if resp.status_code != 200:
            raise Exception(f"Supabase Admin API error: {resp.status_code} {resp.text}")

        users = resp.json().get("users", [])
        matching = [u for u in users if u["email"] == email]
        if not matching:
            raise Exception("User not found in Supabase Auth")
        user_id = matching[0]["id"]

        # Ensure profiles row
        profile_resp = supabase.table("profiles").select("id").eq("id", user_id).execute()
        if not profile_resp.data:
            supabase.table("profiles").insert({
                "id": user_id,
                "email": email,
                "full_name": full_name,
                "ai_enabled": True
            }).execute()

        # Upsert gmail_tokens
        creds_payload = {
            "user_id": user_id,
            "user_email": email,
            "credentials": {
                "token": credentials.token,
                "refresh_token": credentials.refresh_token,
                "token_uri": credentials.token_uri,
                "client_id": credentials.client_id,
                "client_secret": credentials.client_secret,
                "scopes": credentials.scopes
            }
        }
        supabase.table("gmail_tokens").upsert(creds_payload).execute()

        return redirect(f"/complete_profile?user_id={user_id}")

    except Exception as e:
        app.logger.error(f"OAuth2 Callback Error: {str(e)}", exc_info=True)
        return f"<h1>Authentication Failed</h1><p>{str(e)}</p>", 500

@app.route("/complete_profile", methods=["GET", "POST"])
def complete_profile():
    user_id = request.args.get("user_id")
    if not user_id:
        return "Missing user_id", 401

    if request.method == "POST":
        display_name = request.form.get("display_name", "").strip()
        signature    = request.form.get("signature", "").strip()

        supabase.table("profiles") \
            .update({"display_name": display_name,
                     "signature": signature}) \
            .eq("id", user_id) \
            .execute()

        return redirect(f"/dashboard?user_id={user_id}")

    return render_template("complete_profile.html", user_id=user_id)

@app.route("/disconnect_gmail", methods=["POST"])
def disconnect_gmail():
    user_id = request.form.get("user_id")
    supabase.table("gmail_tokens").delete().eq("user_id", user_id).execute()
    return redirect(f"/dashboard?user_id={user_id}")

def _require_user():
    uid = request.args.get("user_id") or request.form.get("user_id")
    if not uid:
        abort(401, "Missing user_id")
    return uid

@app.route("/new_lease", methods=["GET"])
def new_lease_form():
    user_id = _require_user()
    return render_template("new_lease.html", user_id=user_id)

@app.route("/new_lease", methods=["POST"])
def new_lease_submit():
    user_id = _require_user()

    data = {
        "property_name":    request.form["propertyName"],
        "property_type":    request.form["propertyType"],
        "address":          request.form["address"],
        "suite":            request.form.get("suite",""),
        "square_feet":      request.form["squareFeet"],
        "tenant_name":      request.form["tenantName"],
        "tenant_type":      request.form["tenantType"],
        "lease_type":       request.form["leaseType"],
        "lease_term":       request.form["leaseTerm"],
        "start_date":       request.form["startDate"],
        "end_date":         request.form["endDate"],
        "base_rent":        request.form["baseRent"],
        "annual_increase":  request.form.get("annualIncrease",""),
        "security_deposit": request.form.get("securityDeposit",""),
        "parking_spaces":   request.form.get("parkingSpaces",""),
        "parking_fee":      request.form.get("parkingFee",""),
        "additional_terms": request.form.get("additionalTerms",""),
        "tenant_improvements": "Yes" if request.form.get("tenantImprovements") else "No",
        "renewal_option":      "Yes" if request.form.get("renewalOption") else "No",
        "exclusive_use":       "Yes" if request.form.get("exclusiveUse") else "No",
    }

    html_body = f"""
    <html><body>
      <h2>Lease Agreement</h2>
      <p><strong>Property:</strong> {data['property_name']} ({data['property_type'].title()})<br>
      <strong>Address:</strong> {data['address']} Suite {data['suite']}<br>
      <strong>Size:</strong> {data['square_feet']} sqft</p>

      <h3>Tenant</h3>
      <p>{data['tenant_name']} ({data['tenant_type'].title()})</p>

      <h3>Terms</h3>
      <p><strong>Type:</strong> {data['lease_type'].replace('-', ' ').title()}<br>
      <strong>Term:</strong> {data['lease_term']} months<br>
      <strong>Dates:</strong> {data['start_date']} → {data['end_date']}</p>

      <h3>Financials</h3>
      <p><strong>Base Rent:</strong> ${data['base_rent']} per sqft/yr<br>
      <strong>Annual Increase:</strong> {data['annual_increase']}%<br>
      <strong>Security Deposit:</strong> ${data['security_deposit']}<br>
      <strong>Parking:</strong> {data['parking_spaces']} spaces @ ${data['parking_fee']}/mo</p>

      <h3>Additional Terms</h3>
      <p>{data['additional_terms']}</p>
      <ul>
        <li>Tenant Improvements: {data['tenant_improvements']}</li>
        <li>Renewal Option: {data['renewal_option']}</li>
        <li>Exclusive Use Clause: {data['exclusive_use']}</li>
      </ul>
    </body></html>
    """

    tok = (supabase.table("gmail_tokens")
                .select("credentials")
                .eq("user_id", user_id)
                .limit(1)
                .execute()
                .data) or []
    if not tok:
        abort(400, "No Gmail token; reconnect Gmail first.")

    cd = tok[0]["credentials"]
    creds = Credentials(
        token=cd["token"],
        refresh_token=cd["refresh_token"],
        token_uri=cd["token_uri"],
        client_id=cd["client_id"],
        client_secret=cd["client_secret"],
        scopes=cd["scopes"],
    )
    if creds.expired and creds.refresh_token:
        creds.refresh(GoogleRequest())

    service = build("gmail", "v1", credentials=creds, cache_discovery=False)

    mime = MIMEText(html_body, "html")
    mime["To"]      = ""
    mime["Subject"] = f"Draft Lease: {data['property_name']} → {data['tenant_name']}"
    raw = base64.urlsafe_b64encode(mime.as_bytes()).decode()
    draft = {"message": {"raw": raw}}
    created = service.users().drafts().create(userId="me", body=draft).execute()

    app.logger.info(f"Gmail Draft {created['id']} created for user {user_id}")

    return redirect(f"/dashboard?user_id={user_id}")

@app.route("/admin")
def admin():
    return render_template("admin.html")

@app.route("/api/admin/users")
def api_admin_users():
    users = supabase.table("profiles").select("*").execute().data or []
    today = date.today().isoformat()
    results = []
    for user in users:
        sent = supabase.table("emails") \
            .select("sent_at") \
            .eq("user_id", user["id"]) \
            .eq("status", "sent") \
            .execute().data or []
        count = len([e for e in sent if e["sent_at"] and e["sent_at"].startswith(today)])
        results.append({
            "id": user["id"],
            "name": user["full_name"],
            "email": user["email"],
            "enabled": user.get("ai_enabled", True),
            "emails_today": count
        })
    return jsonify(results)

@app.route("/api/admin/toggle_status", methods=["POST"])
def api_toggle_status():
    user_id = request.json.get("user_id")
    enable = request.json.get("enable", True)
    supabase.table("profiles").update({"ai_enabled": enable}).eq("id", user_id).execute()
    return jsonify({"success": True})

@app.route("/debug_env")
def debug_env():
    return {
        "GOOGLE_CLIENT_ID": os.environ.get("GOOGLE_CLIENT_ID"),
        "REDIRECT_URI": os.environ.get("REDIRECT_URI"),
        "EDGE_BASE_URL": os.environ.get("EDGE_BASE_URL")
    }

from datetime import datetime

@app.route("/process", methods=["GET"])
def trigger_process():
    token = request.args.get("token")
    if token != os.environ.get("PROCESS_SECRET_TOKEN"):
        return jsonify({"error": "Unauthorized"}), 401
# ── 0) DAILY RESET CHECK ──
    today_str = date.today().isoformat()
    rl_row = SUPABASE_SERVICE.table("rate_limit_reset") \
        .select("last_reset") \
        .eq("id", "global") \
        .single() \
        .execute().data or {}
    last_date = rl_row.get("last_reset", "")[:10]  # e.g. "2025-07-27"

    if last_date != today_str:
        app.logger.info("🔄 New day detected – clearing emails table")

        # Delete all rows by filtering out a UUID value that never exists
        SUPABASE_SERVICE.table("emails") \
            .delete() \
            .neq("id", "00000000-0000-0000-0000-000000000000") \
            .execute()

        # Update the reset timestamp
        SUPABASE_SERVICE.table("rate_limit_reset") \
            .update({"last_reset": datetime.now(timezone.utc).isoformat()}) \
            .eq("id", "global") \
            .execute()

        
    # ── 0) Build per-user counts of emails already sent today (YYYY‑MM‑DD) ──
    today_iso = datetime.utcnow().date().isoformat()
    sent_rows = (
        supabase.table("emails")
                .select("user_id, sent_at")
                .eq("status", "sent")
                .execute()
                .data or []
    )
    emails_sent_today: dict[str,int] = {}
    for r in sent_rows:
        sent_at = r.get("sent_at","")
        if sent_at.startswith(today_iso):
            uid = r["user_id"]
            emails_sent_today[uid] = emails_sent_today.get(uid, 0) + 1

    # ── 1) Fetch the three pre‑send queues ──
    gen  = supabase.table("emails").select("id").eq("status", "processing").execute().data or []
    per  = supabase.table("emails").select("id").eq("status", "ready_to_personalize").execute().data or []
    prop = supabase.table("emails").select("id").eq("status", "awaiting_proposal").execute().data or []

    if not (gen or per or prop):
        app.logger.info("⚡ No emails to process — returning 204")
        return "", 204

    all_processed, sent, drafted, failed = [], [], [], []

    # ── 2) Generate Response ──
    if gen:
        ids = [r["id"] for r in gen]
        if call_edge("/functions/v1/clever-service/generate-response", {"email_ids": ids}):
            all_processed.extend(ids)
        else:
            supabase.table("emails")\
                    .update({"status":"error","error_message":"generate-response failed"})\
                    .in_("id", ids).execute()

    # ── 3) Personalize Template ──
    if per:
        for eid in [r["id"] for r in per]:
            if call_edge("/functions/v1/clever-service/personalize-template", {"email_ids":[eid]}):
                supabase.table("emails").update({"status":"awaiting_proposal"}).eq("id", eid).execute()
                all_processed.append(eid)
            else:
                supabase.table("emails")\
                        .update({"status":"error","error_message":"personalize-template failed"})\
                        .eq("id", eid).execute()

    # ── 4) Generate Proposal → ready_to_send ──
    if prop:
        for eid in [r["id"] for r in prop]:
            if call_edge("/functions/v1/clever-service/generate-proposal", {"email_ids":[eid]}):
                supabase.table("emails").update({"status":"ready_to_send"}).eq("id", eid).execute()
                all_processed.append(eid)
            else:
                supabase.table("emails")\
                        .update({"status":"error","error_message":"generate-proposal failed"})\
                        .eq("id", eid).execute()

    # ── 5) Re‑fetch ready_to_send rows ──
    ready = (
        supabase.table("emails")
                .select("id, user_id, sender_email, processed_content")
                .eq("status", "ready_to_send")
                .execute()
                .data or []
    )

        # ── 6) Send via SMTP fallback or Gmail API, enforcing 20/day cap ──
    for rec in ready:
        em_id     = rec["id"]
        uid       = rec["user_id"]
        to_addr   = rec["sender_email"]

        # load personalization flags & build HTML
        lease_flag = supabase.table("profiles") \
                             .select("generate_leases") \
                             .eq("id", uid).single().execute().data.get("generate_leases", False)
        body_html = (rec.get("processed_content") or "").replace("\n", "<br>")
        prof_sig = supabase.table("profiles") \
                           .select("display_name, signature") \
                           .eq("id", uid).single().execute().data or {}
        if prof_sig.get("display_name"):
            body_html = body_html.replace("[Your Name]", prof_sig["display_name"])
        full_html = f"<html><body><p>{body_html}</p>{prof_sig.get('signature','')}</body></html>"

        # 20-email/day limit
        if emails_sent_today.get(uid, 0) >= 20:
            app.logger.info(f"User {uid} reached daily limit, marking {em_id} error")
            supabase.table("emails").update({
                "status": "error",
                "error_message": "Daily email limit reached"
            }).eq("id", em_id).execute()
            failed.append(em_id)
            continue

        # 1) SMTP fallback
        prof = supabase.table("profiles") \
                       .select("smtp_email,smtp_enc_password,smtp_host") \
                       .eq("id", uid).single().execute().data or {}
        if prof.get("smtp_email") and prof.get("smtp_enc_password"):
            smtp_email = prof["smtp_email"]
            smtp_pass  = fernet.decrypt(prof["smtp_enc_password"].encode()).decode()
            smtp_host  = prof.get("smtp_host", "smtp.gmail.com")
            try:
                send_email_smtp(
                    smtp_email,
                    smtp_pass,
                    to_addr,
                    "Lease Agreement Draft" if lease_flag else "Re: Your Email",
                    full_html,
                    smtp_host=smtp_host
                )
                supabase.table("emails").update({
                    "status":  "sent",
                    "sent_at": datetime.utcnow().isoformat()
                }).eq("id", em_id).execute()
                emails_sent_today[uid] = emails_sent_today.get(uid, 0) + 1
                sent.append(em_id)
                app.logger.info(f"SMTP send succeeded for email {em_id} (user {uid})")
            except Exception as e:
                app.logger.error(f"SMTP send failed for email {em_id} (user {uid})", exc_info=True)
                supabase.table("emails").update({
                    "status":        "error",
                    "error_message": str(e)
                }).eq("id", em_id).execute()
                failed.append(em_id)
            continue  # next `rec`

        # 2) Gmail API fallback
        try:
            tok = supabase.table("gmail_tokens") \
                          .select("credentials") \
                          .eq("user_id", uid).single().execute().data
            if not tok:
                raise ValueError("No Gmail token found")

            cd = tok["credentials"]
            creds = Credentials(
                token=cd["token"],
                refresh_token=cd["refresh_token"],
                token_uri=cd["token_uri"],
                client_id=cd["client_id"],
                client_secret=cd["client_secret"],
                scopes=cd["scopes"],
            )
            if creds.expired and creds.refresh_token:
                creds.refresh(GoogleRequest())

            svc = build("gmail", "v1", credentials=creds, cache_discovery=False)
            msg = MIMEText(full_html, "html")
            msg["to"]      = to_addr
            msg["from"]    = "me"
            msg["subject"] = "Lease Agreement Draft" if lease_flag else "Re: Your Email"
            raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()

            if lease_flag:
                svc.users().drafts().create(userId="me", body={"message": {"raw": raw}}).execute()
                status_to = "drafted"
                drafted.append(em_id)
            else:
                svc.users().messages().send(userId="me", body={"raw": raw}).execute()
                status_to = "sent"
                sent.append(em_id)

            supabase.table("emails").update({
                "status":  status_to,
                "sent_at": datetime.utcnow().isoformat()
            }).eq("id", em_id).execute()
            emails_sent_today[uid] = emails_sent_today.get(uid, 0) + 1
            app.logger.info(f"Gmail API send succeeded for email {em_id} (user {uid})")

        except Exception as e:
            app.logger.error(f"Gmail API send failed for email {em_id} (user {uid})", exc_info=True)
            supabase.table("emails").update({
                "status":        "error",
                "error_message": str(e)
            }).eq("id", em_id).execute()
            failed.append(em_id)

    # ── Summary response ──
    summary = {
        "processed": all_processed,
        "sent":      sent,
        "drafted":   drafted,
        "failed":    failed
    }
    return jsonify(summary), 200


@app.route("/transaction/<txn_id>/ready", methods=["POST"])
def mark_ready(txn_id):
    supabase.table("transactions").update({"ready_for_kit": True}).eq("id", txn_id).execute()
    return "", 204

@app.route("/autopilot/batch", methods=["POST"])
def batch_autopilot():
    txns = supabase.table("transactions").select("*").eq("ready_for_kit", True).eq("kit_generated", False).execute().data or []
    results = []
    for t in txns:
        payload = {
          "transaction_type": t["transaction_type"],
          "data": {
            "id": t["id"],
            "buyer": t["buyer"],
            "seller": t["seller"],
            "date": t["date"],
            "purchase_price": t["purchase_price"],
            "closing_date": t.get("closing_date"),
            "closing_location": t.get("closing_location")
          }
        }
        resp = requests.post(f"{os.environ.get('BASE_URL')}/autopilot/trigger", json=payload)
        results.append({"id": t["id"], "status": resp.status_code})
        if resp.ok:
            supabase.table("transactions").update({"kit_generated": True}).eq("id", t["id"]).execute()
    return jsonify(results), 200

@app.route("/dashboard/autopilot")
def dashboard_autopilot():
    user_id = request.args.get("user_id") or abort(401)
    txn_id  = request.args.get("txn_id")
    transactions = supabase.table("transactions").select("*").eq("user_id", user_id).execute().data or []
    current_txn = None
    if txn_id:
        resp = supabase.table("transactions").select("*").eq("id", txn_id).execute()
        current_txn = resp.data[0] if resp.data else None
    return render_template("partials/autopilot.html", user_id=user_id, transactions=transactions, current_transaction=current_txn)

@app.route("/transactions/new", methods=["POST"])
def create_transaction():
    import uuid
    import traceback

    user_id = request.args.get("user_id") or request.form.get("user_id")
    if not user_id:
        return jsonify({"status": "error", "message": "Missing user_id"}), 401

    new_id = str(uuid.uuid4())

    # 🔐 Validate required fields (lowercase unified names)
    required = ["buyer_name", "seller_name", "property_address", "agreement_date"]
    missing = [f for f in required if not request.form.get(f)]
    if missing:
        app.logger.warning(f"⚠️ Missing required fields: {missing}")
        return jsonify({
            "status": "error",
            "message": f"Missing required fields: {', '.join(missing)}"
        }), 400

    # ✅ All accepted lowercase fields from gamified form
    accepted_fields = [
        "transaction_type", "property_address", "city", "state", "name_of_property",
        "description_of_property", "square_feet", "legal_description",
        "apartment_address", "premises_description",

        "buyer_name", "buyer_address", "seller_name", "seller_address", "agency_name",

        "purchase_price", "deposit_amount", "agreement_date", "broker_name",
        "commission_amount", "brokerage_fee", "broker_payday",

        "closing_date", "occupy_property_date", "mortgage_amount", "mortgage_years",
        "interest_rate", "inspection_days", "possession_date",

        "rent_type", "agreed_rent", "maintenance_terms",

        "landlord_phone", "tenant_phone", "landlord_email", "tenant_email",

        "structure_age", "location", "county", "additional_explanations",

        "buyer_signature", "seller_signature", "time"
    ]

    # Build the payload, turning empty strings into None
    payload = {"id": new_id, "user_id": user_id}
    for field in accepted_fields:
        val = request.form.get(field)
        payload[field] = None if val == "" else val

    try:
        app.logger.info(f"🚀 Inserting transaction with ID {new_id}")
        app.logger.debug(f"Payload: {payload}")
        resp = supabase.table("transactions").insert(payload).execute()
        inserted = resp.data[0]
    except Exception as e:
        app.logger.error("❌ Transaction insert failed")
        app.logger.error(traceback.format_exc())
        return jsonify({
            "status": "error",
            "message": f"Insertion failed: {str(e)}"
        }), 500

    # ✅ Success response with htmx trigger
    feedback = (
        f'<div class="alert alert-success">🎉 Transaction <strong>{inserted["id"]}</strong> created.</div>'
        + '<script>htmx.trigger(document.querySelector(\'[hx-get*="/dashboard/autopilot"]\'), "click")</script>'
    )
    return feedback, 200




# ── Final entry point ──
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
