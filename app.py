import os
import time
import base64
import requests

from flask import abort, Flask, render_template, request, redirect, jsonify
from datetime import date, datetime
from email.mime.text import MIMEText

from supabase import create_client, Client

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleRequest
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
import google.auth.transport.requests as grequests

# bring in your Blueprints
from transaction_autopilot import bp as autopilot_bp
from public import public_bp

# ── single Flask app & blueprint registration ──
app = Flask(__name__, template_folder="templates")
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret")
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

# Retry configuration for calling the Edge Function
MAX_RETRIES = 5
RETRY_BACKOFF_BASE = 2

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

    if request.method == "POST":
        # Only handling profile section here; you can extend for security/integrations
        new_display_name = request.form.get("display_name", "").strip()
        new_signature    = request.form.get("signature", "").strip()

        # Persist updates
        supabase.table("profiles") \
                .update({
                    "display_name": new_display_name,
                    "signature":    new_signature
                }) \
                .eq("id", user_id) \
                .execute()

    # On both GET and after POST, re‑fetch the latest profile
    profile = (
        supabase
        .table("profiles")
        .select("display_name, signature, ai_enabled")
        .eq("id", user_id)
        .single()
        .execute()
        .data
    )

    return render_template(
        "partials/settings.html",
        profile=profile,
        user_id=user_id
    )


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

@app.route("/process", methods=["GET"])
def trigger_process():
    token = request.args.get("token")
    if token != os.environ.get("PROCESS_SECRET_TOKEN"):
        return jsonify({"error": "Unauthorized"}), 401

    gen   = supabase.table("emails").select("id").eq("status", "processing").execute().data or []
    per   = supabase.table("emails").select("id").eq("status", "ready_to_personalize").execute().data or []
    prop  = supabase.table("emails").select("id").eq("status", "awaiting_proposal").execute().data or []
    ready = supabase.table("emails").select("id").eq("status", "ready_to_send").execute().data or []

    if not (gen or per or prop or ready):
        app.logger.info("⚡ No emails to process — returning 204")
        return "", 204

    all_processed = []
    sent, drafted, failed = [], [], []

    # Stage 1: Generate Response
    if gen:
        ids = [r["id"] for r in gen]
        if call_edge("/functions/v1/clever-service/generate-response", {"email_ids": ids}):
            all_processed.extend(ids)
        else:
            supabase.table("emails").update({"status": "error", "error_message": "generate-response failed"}).in_("id", ids).execute()

    # Stage 2: Personalize Template
    if per:
        for eid in [r["id"] for r in per]:
            if call_edge("/functions/v1/clever-service/personalize-template", {"email_ids": [eid]}):
                supabase.table("emails").update({"status": "awaiting_proposal"}).eq("id", eid).execute()
                all_processed.append(eid)
            else:
                supabase.table("emails").update({"status": "error", "error_message": "personalize-template failed"}).eq("id", eid).execute()

    # Stage 3: Generate Proposal
    if prop:
        for eid in [r["id"] for r in prop]:
            if call_edge("/functions/v1/clever-service/generate-proposal", {"email_ids": [eid]}):
                supabase.table("emails").update({"status": "ready_to_send"}).eq("id", eid).execute()
                all_processed.append(eid)
            else:
                supabase.table("emails").update({"status": "error", "error_message": "generate-proposal failed"}).eq("id", eid).execute()

    # Stage 4: Send or Draft via Gmail
    for r in (supabase.table("emails")
                    .select("id, user_id, sender_email, processed_content")
                    .eq("status", "ready_to_send")
                    .execute().data or []):
        em_id      = r["id"]
        uid        = r["user_id"]
        to_addr    = r.get("sender_email")
        html_body  = (r.get("processed_content") or "").replace("\n", "<br>")

        prof = supabase.table("profiles").select("display_name, signature, generate_leases").eq("id", uid).single().execute().data or {}
        display, sig, lease_flag = prof.get("display_name",""), prof.get("signature",""), prof.get("generate_leases", False)
        if display:
            html_body = html_body.replace("[Your Name]", display)

        full_html = f"<html><body><p>{html_body}</p>{sig}</body></html>"

        tok = (supabase.table("gmail_tokens").select("credentials").eq("user_id", uid).limit(1).execute().data) or []
        if not tok:
            failed.append(em_id)
            supabase.table("emails").update({"status":"error","error_message":"No Gmail token"}).eq("id", em_id).execute()
            continue

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
        svc = build("gmail", "v1", credentials=creds, cache_discovery=False)

        try:
            msg = MIMEText(full_html, "html")
            msg["to"]    = to_addr
            msg["from"]  = "me"
            subject = "Lease Agreement Draft" if lease_flag else "Re: Your Email"
            msg["subject"] = subject
            raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()

            if lease_flag:
                svc.users().drafts().create(userId="me", body={"message": {"raw": raw}}).execute()
                drafted.append(em_id)
            else:
                svc.users().messages().send(userId="me", body={"raw": raw}).execute()
                sent.append(em_id)

            supabase.table("emails").update({
                "status": "drafted" if lease_flag else "sent",
                "sent_at": datetime.utcnow().isoformat()
            }).eq("id", em_id).execute()
        except Exception as e:
            failed.append(em_id)
            supabase.table("emails").update({"status":"error","error_message":str(e)}).eq("id", em_id).execute()

    summary = {"processed": all_processed, "sent": sent, "drafted": drafted, "failed": failed}
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

    # 🔐 Validate required fields
    required = ["Buyer_Name", "Seller_Name", "Property_Address", "Agreement_Date"]
    missing = [f for f in required if not request.form.get(f)]
    if missing:
        app.logger.warning(f"⚠️ Missing required fields: {missing}")
        return jsonify({"status": "error", "message": f"Missing required fields: {', '.join(missing)}"}), 400

    # ✅ All accepted fields from gamified form
    accepted_fields = [
        "transaction_type", "property_address", "buyer", "seller", "date", "closing_date",
        "purchase_price", "closing_location", "Buyer_Name", "Buyer_Address", "Seller_Name",
        "Seller_Address", "Agreement_Date", "Buyer_Signature", "Seller_Signature",
        "Deposit_Amount", "Legal_Description", "Broker_Name", "Commission_Amount",
        "occupy_property_date", "structure_age", "Additional_explanations", "Time",
        "Name_of_Property", "City", "County", "State", "Description_of_Property",
        "square_feet", "mortgage_amount", "mortgage_years", "interest_rate", "broker_payday",
        "inspection_days", "possession_Date", "brokerage_fee", "Location", "Rent_type",
        "Apartment_address", "Apartment_description", "Premises_description", "Lease_Terms",
        "Agreed_Rent", "Maintenance_terms", "Landlord_Phone", "Tenant_Phone",
        "Landlord_Email", "Tenant_Email", "agency_Name"
    ]

    payload = {"id": new_id, "user_id": user_id}
    for field in accepted_fields:
        value = request.form.get(field)
        payload[field] = None if value == "" else value

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
