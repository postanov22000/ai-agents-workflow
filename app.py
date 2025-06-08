import os
import time
import base64
import requests

from flask import abort
from datetime import date, datetime
from email.mime.text import MIMEText

from flask import Flask, render_template, request, redirect, jsonify

from supabase import create_client, Client

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleRequest
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
import google.auth.transport.requests as grequests

app = Flask(__name__, template_folder="templates")
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret")

# --- Supabase setup ---
SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_ANON_KEY = os.environ["SUPABASE_ANON_KEY"]
SUPABASE_SERVICE_ROLE_KEY = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

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
    """
    Renders the dashboard for a given user_id, including the
    'generate_leases' toggle pulled from the profiles table.
    """
    user_id = request.args.get("user_id")
    if not user_id:
        return "Missing user_id", 401

    # Fetch the user’s profile including our new generate_leases flag
    profile_resp = supabase.table("profiles") \
        .select("full_name, ai_enabled, email, generate_leases") \
        .eq("id", user_id) \
        .single() \
        .execute()

    if profile_resp.error:
        return f"Profile query error: {profile_resp.error.message}", 500

    profile = profile_resp.data or {}
    full_name = profile.get("full_name", "")
    ai_enabled = profile.get("ai_enabled", True)
    generate_leases = profile.get("generate_leases", False)

    # Calculate emails sent today and time saved
    today = date.today().isoformat()
    sent_resp = supabase.table("emails") \
        .select("sent_at") \
        .eq("user_id", user_id) \
        .eq("status", "sent") \
        .execute()

    sent = sent_resp.data or []
    emails_sent_today = len([e for e in sent if e["sent_at"] and e["sent_at"].startswith(today)])
    time_saved = emails_sent_today * 5.5

    # Check Gmail token status to decide whether to show "Reconnect" button
    token_resp = supabase.table("gmail_tokens") \
        .select("credentials") \
        .eq("user_id", user_id) \
        .execute()

    show_reconnect = True
    if token_resp.data:
        creds_data = token_resp.data[0]["credentials"]
        try:
            creds = Credentials(
                token=creds_data["token"],
                refresh_token=creds_data["refresh_token"],
                token_uri=creds_data["token_uri"],
                client_id=creds_data["client_id"],
                client_secret=creds_data["client_secret"],
                scopes=creds_data["scopes"],
            )
            if not creds.expired:
                show_reconnect = False
        except Exception:
            # any parsing/refresh error just falls back to showing reconnect
            pass

    return render_template(
        "dashboard.html",
        name=full_name,
        user_id=user_id,
        emails_sent=emails_sent_today,
        time_saved=time_saved,
        ai_enabled=ai_enabled,
        show_reconnect=show_reconnect,
        generate_leases=generate_leases,   # ← now correctly passed in
    )


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


@app.route("/toggle_leases", methods=["POST"])
def toggle_leases():
    """
    HTMX endpoint to flip a user's `generate_leases` flag on/off.
    Expects form data: user_id.
    """
    user_id = request.form.get("user_id")
    if not user_id:
        return "Missing user_id", 400

    # 1) Fetch current setting
    profile_resp = supabase.table("profiles") \
        .select("generate_leases") \
        .eq("id", user_id) \
        .single() \
        .execute()

    if profile_resp.error:
        app.logger.error(f"Error reading generate_leases for {user_id}: {profile_resp.error.message}")
        return "Database error", 500

    current = profile_resp.data.get("generate_leases", False)

    # 2) Toggle it
    new_val = not current
    upd_resp = supabase.table("profiles") \
        .update({"generate_leases": new_val}) \
        .eq("id", user_id) \
        .execute()

    if upd_resp.error:
        app.logger.error(f"Error updating generate_leases for {user_id}: {upd_resp.error.message}")
        return "Database error", 500

    # 3) Return no content (HTMX will happily leave the toggle in its new state)
    return ("", 204)

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
      5) Send via Gmail (ready_to_send → sent, with real name & HTML signature)
    """
    # 1) Token‐based auth
    token = request.args.get("token")
    if token != os.environ.get("PROCESS_SECRET_TOKEN"):
        return "Unauthorized", 401

    all_processed = []

    #### STAGE 1 → Detect Jargon
    jargon_rows = (supabase.table("emails")
                         .select("id, original_content")
                         .eq("status", "preprocessing")
                         .execute().data or [])
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
    resp_pending = (supabase.table("emails")
                          .select("id")
                          .eq("status", "awaiting_response")
                          .execute().data or [])
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
    per_pending = (supabase.table("emails")
                          .select("id, template_text, past_emails, deal_data")
                          .eq("status", "ready_to_personalize")
                          .execute().data or [])
    if per_pending:
        ids = [r["id"] for r in per_pending]
        supabase.table("emails").update({"status": "processing"}).in_("id", ids).execute()
        for r in per_pending:
            payload = {
                "template_text": r["template_text"] or "",
                "past_emails":   r["past_emails"] or [],
                "deal_data":     r["deal_data"] or {}
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
    prop_pending = (supabase.table("emails")
                           .select("id, market, deal_type, cap_rate, tenant_type, style")
                           .eq("status", "awaiting_proposal")
                           .execute().data or [])
    if prop_pending:
        ids = [r["id"] for r in prop_pending]
        supabase.table("emails").update({"status": "processing"}).in_("id", ids).execute()
        for r in prop_pending:
            payload = {
                "market":      r["market"],
                "deal_type":   r["deal_type"],
                "cap_rate":    r["cap_rate"],
                "tenant_type": r["tenant_type"],
                "style":       r["style"]
            }
            if call_edge("/generate-proposal", payload):
                supabase.table("emails").update({"status": "ready_to_send"}).eq("id", r["id"]).execute()
                all_processed.append(r["id"])
            else:
                supabase.table("emails").update({
                    "status": "error",
                    "error_message": "generate-proposal failed"
                }).eq("id", r["id"]).execute()

    #### STAGE 5 → Send via Gmail (with real name & HTML signature)
    sent, failed = [], []
    ready_list = (supabase.table("emails")
                         .select("id, user_id, sender_email, processed_content")
                         .eq("status", "ready_to_send")
                         .execute().data or [])

    for r in ready_list:
        em_id    = r["id"]
        uid      = r["user_id"]
        to_addr  = r["sender_email"]
        ai_text  = (r["processed_content"] or "").rstrip()

        # 1) fetch display_name + HTML signature
        prof = (supabase.table("profiles")
                        .select("display_name, signature")
                        .eq("id", uid)
                        .single()
                        .execute().data) or {}
        name = prof.get("display_name", "").strip()
        sig  = prof.get("signature", "").strip()

        # 2) replace “[Your Name]” placeholder
        if name:
            ai_text = ai_text.replace("[Your Name]", name)

        # 3) build HTML body
        body_html = (
            "<html><body>"
            + "<p>" + ai_text.replace("\n", "<br>") + "</p>"
            + (sig or "")
            + "</body></html>"
        )

        # 4) load Gmail creds and send
        tok = (supabase.table("gmail_tokens")
                      .select("credentials")
                      .eq("user_id", uid)
                      .limit(1)
                      .execute().data) or []
        if not tok:
            app.logger.warning(f"No Gmail token for {uid}, skipping {em_id}")
            failed.append(em_id)
            supabase.table("emails").update({
                "status": "error", "error_message": "No Gmail token"
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
        if creds.expired and creds.refresh_token:
            creds.refresh(GoogleRequest())

        try:
            svc = build("gmail", "v1", credentials=creds, cache_discovery=False)
            msg = MIMEText(body_html, "html")
            msg["to"]      = to_addr
            msg["from"]    = "me"
            msg["subject"] = "Re: your email"
            raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
            send_res = svc.users().messages().send(userId="me", body={"raw": raw}).execute()

            supabase.table("emails").update({
                "status": "sent",
                "sent_at": datetime.utcnow().isoformat()
            }).eq("id", em_id).execute()

            sent.append(em_id)
            app.logger.info(f"Sent {em_id} → Gmail ID {send_res.get('id')}")
        except Exception as e:
            failed.append(em_id)
            app.logger.error(f"Send failed for {em_id}: {e}", exc_info=True)
            supabase.table("emails").update({
                "status": "error",
                "error_message": str(e)
            }).eq("id", em_id).execute()

    return jsonify({
        "processed": all_processed,
        "sent":      sent,
        "failed":    failed,
        "summary":   f"{len(sent)} sent, {len(failed)} failed, {len(all_processed)} processed"
    }), 200




# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
