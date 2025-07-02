import os
import time
import base64
import requests

from flask import abort
from datetime import date, datetime
from email.mime.text import MIMEText

from flask import Flask, render_template, request, redirect, jsonify, render_template_string

from supabase import create_client, Client

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleRequest
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
import google.auth.transport.requests as grequests

# bring in your Blueprint (which has /autopilot/trigger, etc.)
from transaction_autopilot import bp as autopilot_bp

# bring in your stand-alone task version (if you ever call it directly)
import transaction_autopilot_task

# ── single Flask app & blueprint registration ──
app = Flask(__name__, template_folder="templates")
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret")
app.register_blueprint(autopilot_bp, url_prefix="/autopilot")

# --- Supabase setup ---
SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_ANON_KEY = os.environ["SUPABASE_ANON_KEY"]
SUPABASE_SERVICE_ROLE_KEY = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
# Service‐role client (needed to update tokens)
SUPABASE_SERVICE: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
# Edge Function base URL *without* trailing slash or endpoint
# e.g. "https://<PROJECT_REF>.functions.supabase.co/functions/v1/clever-service"
EDGE_BASE_URL = os.environ.get("EDGE_BASE_URL", "").rstrip("/")

# Retry configuration for calling the Edge Function
MAX_RETRIES = 5
RETRY_BACKOFF_BASE = 2

# ---------------------------------------------------------------------------
def call_edge(endpoint_path: str, payload: dict) -> bool:
    """
    POSTs `payload` to the clever-service endpoint at:
      EDGE_BASE_URL + endpoint_path
    Retries up to MAX_RETRIES times on 429. Returns True if status_code == 200.
    """
    url = f"{EDGE_BASE_URL}{endpoint_path}"
    headers = {
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "apikey":        SUPABASE_SERVICE_ROLE_KEY,
        "Content-Type":  "application/json"
    }

    for attempt in range(MAX_RETRIES):
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=60)
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

# ---------------------------------------------------------------------------
@app.route("/")
def home():
    """
    Redirect to /dashboard with a user_id parameter.
    """
    user_id = request.args.get("user_id")
    if user_id:
        return redirect(f"/dashboard?user_id={user_id}")
    return "Missing user_id", 401

@app.route("/dashboard")
def dashboard():
    user_id = request.args.get("user_id")
    if not user_id:
        return "Missing user_id", 401

    # 1) Profile
    profile_resp = (
        supabase.table("profiles")
                .select("full_name, ai_enabled, email, generate_leases")
                .eq("id", user_id)
                .single()
                .execute()
    )
    if profile_resp.data is None:
        app.logger.error(f"Failed to load profile for {user_id}: {profile_resp}")
        return "Profile query error", 500

    profile        = profile_resp.data
    full_name      = profile.get("full_name", "")
    ai_enabled     = profile.get("ai_enabled", True)
    generate_leases = profile.get("generate_leases", False)

    # 2) Emails sent today & time saved
    today       = date.today().isoformat()
    sent_rows   = (
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

    # 3) Gmail token status
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
        "dashboard.html",
        name=full_name,
        user_id=user_id,
        emails_sent=emails_sent_today,
        time_saved=time_saved,
        ai_enabled=ai_enabled,
        show_reconnect=show_reconnect,
        generate_leases=generate_leases,
    )

@app.route("/dashboard/new_transaction")
def dashboard_new_transaction():
    user_id = request.args.get("user_id") or abort(401)
    return render_template("partials/new_transaction.html", user_id=user_id)


@app.route("/dashboard/analytics")
def dashboard_analytics():
    user_id = _require_user()
    # load whatever data you need for analytics:
    # e.g. charts, tables, etc.
    # For now we’ll just show a placeholder.
    return render_template(
        "partials/analytics.html",
        user_id=user_id,
        # pass any metrics or data here...
    )

@app.route("/dashboard/users")
def dashboard_users():
    user_id = _require_user()
    # fetch your users list from Supabase:
    users = supabase.table("profiles").select("id, full_name, email").execute().data or []
    return render_template(
        "partials/users.html",
        users=users
    )

@app.route("/dashboard/billing")
def dashboard_billing():
    user_id = _require_user()
    # load any billing info you need:
    # e.g. invoices, plan status…
    return render_template(
        "partials/billing.html",
        user_id=user_id
    )

@app.route("/dashboard/settings")
def dashboard_settings():
    user_id = _require_user()
    profile = supabase.table("profiles").select("display_name, signature, ai_enabled").eq("id", user_id).single().execute().data
    return render_template(
        "partials/settings.html",
        profile=profile,
        user_id=user_id
    )

@app.route("/dashboard/home")
def dashboard_home():
    """HTMX endpoint: only renders the inner `.main-content`."""
    user_id = request.args.get("user_id")
    if not user_id:
        return "Missing user_id", 401

    # (Exact same logic as /dashboard, so all vars are defined)
    profile_resp = (
        supabase.table("profiles")
                .select("full_name, ai_enabled, email, generate_leases")
                .eq("id", user_id)
                .single()
                .execute()
    )
    if profile_resp.data is None:
        return "Profile query error", 500

    profile        = profile_resp.data
    full_name      = profile.get("full_name", "")
    ai_enabled     = profile.get("ai_enabled", True)
    generate_leases = profile.get("generate_leases", False)

    today       = date.today().isoformat()
    sent_rows   = (
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

    token_rows    = (
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
    Handles OAuth2 callback from Google:
      - Verifies ID token
      - Finds or creates Supabase profile
      - Upserts Gmail credentials in supabase.gmail_tokens
      - Redirects to /complete-profile so the user can enter their display name & signature
    """
    try:
        # Reconstruct the OAuth flow
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

        # Verify the ID token to get the user's email (and possibly name)
        id_info = id_token.verify_oauth2_token(
            credentials.id_token,
            grequests.Request(),
            os.environ["GOOGLE_CLIENT_ID"]
        )
        email = id_info.get("email")
        full_name = id_info.get("name") or email.split("@")[0]

        if not email:
            raise ValueError("No email found in Google ID token")

        # Use Supabase Admin API to look up the Auth user by email
        auth_url = f"{SUPABASE_URL}/auth/v1/admin/users"
        headers = {
            "apikey": SUPABASE_SERVICE_ROLE_KEY,
            "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}"
        }
        resp = requests.get(auth_url, headers=headers, params={"email": email})
        if resp.status_code != 200:
            raise Exception(f"Supabase Admin API error: {resp.status_code} {resp.text}")

        users = resp.json().get("users", [])
        matching_users = [u for u in users if u["email"] == email]
        if not matching_users:
            raise Exception("User not found in Supabase Auth")

        user_id = matching_users[0]["id"]

        # Ensure a row exists in the "profiles" table (with at least id & email)
        profile_resp = supabase.table("profiles").select("id").eq("id", user_id).execute()
        if not profile_resp.data:
            supabase.table("profiles").insert({
                "id": user_id,
                "email": email,
                "full_name": full_name,
                "ai_enabled": True
            }).execute()

        # Store or update the Gmail credentials in supabase.gmail_tokens
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

        # Redirect to the "complete profile" page so the user can enter their display name & signature
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
            .update({
                "display_name": display_name,
                "signature": signature
            }) \
            .eq("id", user_id) \
            .execute()

        return redirect(f"/dashboard?user_id={user_id}")

    # On GET, render your full styled template
    return render_template("complete_profile.html", user_id=user_id)


@app.route("/disconnect_gmail", methods=["POST"])
def disconnect_gmail():
    """
    Deletes the Gmail token for a user.
    """
    user_id = request.form.get("user_id")
    supabase.table("gmail_tokens").delete().eq("user_id", user_id).execute()
    return redirect(f"/dashboard?user_id={user_id}")


# … your existing imports, supabase setup, etc. …

def _require_user():
    # allow user_id via ?user_id= or form field
    uid = request.args.get("user_id") or request.form.get("user_id")
    if not uid:
        abort(401, "Missing user_id")
    return uid

@app.route("/new_lease", methods=["GET"])
def new_lease_form():
    """
    Renders the Create New Lease form.
    """
    user_id = _require_user()
    return render_template("new_lease.html", user_id=user_id)

@app.route("/new_lease", methods=["POST"])
def new_lease_submit():
    """
    Receives the lease form, builds simple HTML,
    and creates a Gmail Draft in the user’s account.
    """
    user_id = _require_user()

    # 1) collect all your form fields into a dict
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

    # 2) render a minimal HTML body for your lease
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

    # 3) fetch the user’s Gmail creds from Supabase
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

    # 4) build MIME and create draft
    mime = MIMEText(html_body, "html")
    mime["To"]      = ""  # leave blank in draft
    mime["Subject"] = f"Draft Lease: {data['property_name']} → {data['tenant_name']}"
    raw = base64.urlsafe_b64encode(mime.as_bytes()).decode()
    draft = {"message": {"raw": raw}}
    created = service.users().drafts().create(userId="me", body=draft).execute()

    app.logger.info(f"Gmail Draft {created['id']} created for user {user_id}")

    # 5) send them back to dashboard
    return redirect(f"/dashboard?user_id={user_id}")



@app.route("/admin")
def admin():
    """
    Renders an admin dashboard (should be protected in production).
    """
    return render_template("admin.html")

@app.route("/api/admin/users")
def api_admin_users():
    """
    Returns JSON of all profiles and their daily email count.
    """
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
    """
    Toggles AI-enabled status for a given user_id.
    """
    user_id = request.json.get("user_id")
    enable = request.json.get("enable", True)
    supabase.table("profiles").update({"ai_enabled": enable}).eq("id", user_id).execute()
    return jsonify({"success": True})

@app.route("/debug_env")
def debug_env():
    """
    Returns key environment variables for debugging.
    """
    return {
        "GOOGLE_CLIENT_ID": os.environ.get("GOOGLE_CLIENT_ID"),
        "REDIRECT_URI": os.environ.get("REDIRECT_URI"),
        "EDGE_BASE_URL": os.environ.get("EDGE_BASE_URL")
    }

@app.route("/process")
def trigger_process():
    """
    Main processing pipeline endpoint. Call this with:
      GET /process?token=<PROCESS_SECRET_TOKEN>
    Pipeline steps:
      1) Detect Jargon
      2) Generate Response
      3) Personalize Template
      4) Generate Proposal
      5) If generate_leases ON → create Gmail Draft
         Else → send via Gmail
    """
    # 1) Token‐based auth
    token = request.args.get("token")
    if token != os.environ.get("PROCESS_SECRET_TOKEN"):
        return "Unauthorized", 401

    all_processed = []

    #### STAGE 1 → Detect Jargon
    jargon_rows = (
        supabase.table("emails")
                .select("id, original_content")
                .eq("status", "preprocessing")
                .execute().data
        or []
    )
    if jargon_rows:
        ids = [r["id"] for r in jargon_rows]
        supabase.table("emails").update({"status": "processing"}).in_("id", ids).execute()
        for r in jargon_rows:
            if call_edge("/detect-jargon", {"text": r["original_content"]}):
                supabase.table("emails").update({"status": "awaiting_response"}).eq("id", r["id"]).execute()
                all_processed.append(r["id"])
            else:
                supabase.table("emails").update({
                    "status": "error",
                    "error_message": "detect-jargon failed"
                }).eq("id", r["id"]).execute()

    #### STAGE 2 → Generate Response
    resp_pending = (
        supabase.table("emails")
                .select("id")
                .eq("status", "awaiting_response")
                .execute().data
        or []
    )
    if resp_pending:
        ids = [r["id"] for r in resp_pending]
        supabase.table("emails").update({"status": "processing"}).in_("id", ids).execute()
        if call_edge("/generate-response", {"email_ids": ids}):
            for eid in ids:
                supabase.table("emails").update({"status": "ready_to_send"}).eq("id", eid).execute()
                all_processed.append(eid)
        else:
            supabase.table("emails").update({
                "status": "error",
                "error_message": "generate-response failed"
            }).in_("id", ids).execute()

    #### STAGE 3 → Personalize Template
    per_pending = (
        supabase.table("emails")
                .select("id, template_text, past_emails, deal_data")
                .eq("status", "ready_to_personalize")
                .execute().data
        or []
    )
    if per_pending:
        ids = [r["id"] for r in per_pending]
        supabase.table("emails").update({"status": "processing"}).in_("id", ids).execute()
        for r in per_pending:
            payload = {
                "template_text": r.get("template_text", ""),
                "past_emails":   r.get("past_emails", []),
                "deal_data":     r.get("deal_data", {})
            }
            if call_edge("/personalize-template", payload):
                supabase.table("emails").update({"status": "awaiting_proposal"}).eq("id", r["id"]).execute()
                all_processed.append(r["id"])
            else:
                supabase.table("emails").update({
                    "status": "error",
                    "error_message": "personalize-template failed"
                }).eq("id", r["id"]).execute()

    #### STAGE 4 → Generate Proposal
    prop_pending = (
        supabase.table("emails")
                .select("id, market, deal_type, cap_rate, tenant_type, style")
                .eq("status", "awaiting_proposal")
                .execute().data
        or []
    )
    if prop_pending:
        ids = [r["id"] for r in prop_pending]
        supabase.table("emails").update({"status": "processing"}).in_("id", ids).execute()
        for r in prop_pending:
            payload = {
                "market":      r.get("market"),
                "deal_type":   r.get("deal_type"),
                "cap_rate":    r.get("cap_rate"),
                "tenant_type": r.get("tenant_type"),
                "style":       r.get("style")
            }
            if call_edge("/generate-proposal", payload):
                supabase.table("emails").update({"status": "ready_to_send"}).eq("id", r["id"]).execute()
                all_processed.append(r["id"])
            else:
                supabase.table("emails").update({
                    "status": "error",
                    "error_message": "generate-proposal failed"
                 }).eq("id", r["id"]).execute()
    
    
        #### STAGE 5 → Send or Draft via Gmail
    sent, drafted, failed = [], [], []
    ready_list = (
        supabase.table("emails")
                .select("id, user_id, sender_email, processed_content")
                .eq("status", "ready_to_send")
                .execute().data
        or []
    )

    for r in ready_list:
        em_id   = r["id"]
        uid     = r["user_id"]
        to_addr = r["sender_email"]
        ai_text = (r.get("processed_content") or "").rstrip()

        # ── fetch user’s name, signature & lease‐toggle ──
        prof = supabase.table("profiles") \
                .select("display_name, signature, generate_leases") \
                .eq("id", uid).single().execute().data or {}
        name            = prof.get("display_name", "").strip()
        sig             = prof.get("signature", "").strip()
        generate_leases = prof.get("generate_leases", False)

        # ── substitute placeholder ──
        if name:
            ai_text = ai_text.replace("[Your Name]", name)

        # ── assemble HTML body ──
        html_body = (
            "<html><body>"
            + "<p>" + ai_text.replace("\n", "<br>") + "</p>"
            + (sig or "")
            + "</body></html>"
        )

        # ── get Gmail creds ──
        tok = supabase.table("gmail_tokens") \
                     .select("credentials") \
                     .eq("user_id", uid).limit(1).execute().data or []
        if not tok:
            app.logger.warning(f"No Gmail token for user {uid}, skipping {em_id}")
            failed.append(em_id)
            supabase.table("emails").update({
                "status": "error",
                "error_message": "No Gmail token"
            }).eq("id", em_id).execute()
            continue

        cd = tok[0]["credentials"]
        creds = Credentials(
            token=cd["token"],
            refresh_token=cd["refresh_token"],
            token_uri=cd["token_uri"],
            client_id=cd["client_id"],
            client_secret=cd["client_secret"],
            scopes=cd["scopes"]
        )

        # ── REFRESH + PERSIST ──
        if creds.expired and creds.refresh_token:
            app.logger.info(f"Token expired for user {uid}; refreshing now.")
            creds.refresh(GoogleRequest())

            # Persist via service‐role client
            resp = SUPABASE_SERVICE.table("gmail_tokens") \
                .update({
                    "credentials": {
                        "token": creds.token,
                        "refresh_token": creds.refresh_token,
                        "token_uri": creds.token_uri,
                        "client_id": creds.client_id,
                        "client_secret": creds.client_secret,
                        "scopes": creds.scopes
                    }
                }) \
                .eq("user_id", uid) \
                .execute()
            app.logger.info(f"Persisted refreshed token for {uid}: data={resp.data}, error={resp.error}")
            if resp.error:
                app.logger.error(f"Failed to persist refreshed token for {uid}: {resp.error}")
                failed.append(em_id)
                continue

        svc = build("gmail", "v1", credentials=creds, cache_discovery=False)

        try:
            if generate_leases:
                # ── create a Gmail Draft ──
                msg = MIMEText(html_body, "html")
                msg["to"]      = to_addr
                msg["from"]    = "me"
                msg["subject"] = "Lease Agreement Draft"
                raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()

                draft_res = svc.users().drafts().create(
                    userId="me",
                    body={"message": {"raw": raw}}
                ).execute()

                drafted.append(em_id)
                app.logger.info(f"Drafted lease for {em_id} → Draft ID {draft_res['id']}")
                supabase.table("emails").update({
                    "status": "drafted",
                    "sent_at": datetime.utcnow().isoformat()
                }).eq("id", em_id).execute()
            else:
                # ── send immediately ──
                msg = MIMEText(html_body, "html")
                msg["to"]      = to_addr
                msg["from"]    = "me"
                msg["subject"] = "Re: your email"
                raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()

                send_res = svc.users().messages().send(
                    userId="me", body={"raw": raw}
                ).execute()

                sent.append(em_id)
                app.logger.info(f"Sent email {em_id} → Gmail ID {send_res.get('id')}")
                supabase.table("emails").update({
                    "status": "sent",
                    "sent_at": datetime.utcnow().isoformat()
                }).eq("id", em_id).execute()
        except Exception as e:
            failed.append(em_id)
            app.logger.error(f"Error processing {em_id}: {e}", exc_info=True)
            supabase.table("emails").update({
                "status": "error",
                "error_message": str(e)
            }).eq("id", em_id).execute()

    return jsonify({
        "sent":      sent,
        "drafted":   drafted,
        "failed":    failed,
        "summary":   f"{len(sent)} sent, {len(drafted)} drafted, {len(failed)} failed"
    }), 200





@app.route("/transaction/<txn_id>/ready", methods=["POST"])
def mark_ready(txn_id):
    supabase.table("transactions")\
            .update({"ready_for_kit": True})\
            .eq("id", txn_id)\
            .execute()
    return "", 204



@app.route("/autopilot/batch", methods=["POST"])
def batch_autopilot():
    # 1) Fetch all transactions ready for kit
    txns = supabase.table("transactions") \
                   .select("*") \
                   .eq("ready_for_kit", True) \
                   .eq("kit_generated", False) \
                   .execute().data or []

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
            supabase.table("transactions") \
                    .update({"kit_generated": True}) \
                    .eq("id", t["id"]) \
                    .execute()

    return jsonify(results), 200


@app.route("/dashboard/autopilot")
def dashboard_autopilot():
    user_id = request.args.get("user_id") or abort(401)
    txn_id  = request.args.get("txn_id")
    # Fetch all the user’s transactions so the dropdown can populate
    transactions = (
        supabase.table("transactions")
                .select("*")
                .eq("user_id", user_id)
                .execute()
                .data
        or []
    )
    current_txn = None
    if txn_id:
        # safe .single() only if exists
        resp = supabase.table("transactions").select("*").eq("id", txn_id).execute()
        current_txn = resp.data[0] if resp.data else None

    return render_template(
        "partials/autopilot.html",
        user_id=user_id,
        transactions=transactions,
        current_transaction=current_txn
    )

from flask import request, redirect, render_template, abort

import uuid
from flask import request, abort, jsonify

@app.route("/transactions/new", methods=["POST"])
def create_transaction():
    # 1) require user
    user_id = request.args.get("user_id") or request.form.get("user_id")
    if not user_id:
        abort(401, "Missing user_id")

    # 2) generate id & collect form data
    new_id = str(uuid.uuid4())
    payload = {
        "id":                new_id,
        "transaction_type":  request.form["transaction_type"],
        "property_address":  request.form["property_address"],
        "buyer":             request.form["buyer"],
        "seller":            request.form["seller"],
        "date":              request.form["date"],
        "closing_date":      request.form.get("closing_date"),
        "purchase_price":    request.form.get("purchase_price"),
        "closing_location":  request.form.get("closing_location"),
        "user_id":           user_id,
    }

    # 3) insert into Supabase
    try:
        resp = supabase.table("transactions").insert(payload).execute()
        inserted = resp.data[0]  # your new row
    except Exception as e:
        # PostgREST will raise on constraint errors, etc.
        return jsonify({"status": "error", "message": str(e)}), 500

    # 4) return success feedback and auto‑reload the Autopilot partial
    feedback = (
      f'<div class="alert alert-success">Transaction <strong>{inserted["id"]}</strong> created.</div>'
      # trigger a reload of the Autopilot tab so the new txn shows up
      + '<script>htmx.trigger(document.querySelector(\'[hx-get*="/dashboard/autopilot"]\'), "click")</script>'
    )
    return feedback, 200




# ---------------------------------------------------------------------------


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
