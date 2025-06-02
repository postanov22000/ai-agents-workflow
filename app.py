import base64
import os
import json
import requests
from google.auth.transport.requests import Request as GoogleRequest
from datetime import date, datetime
from email.mime.text import MIMEText
from flask import abort
from googleapiclient.discovery import build
from flask import Flask, render_template, request, redirect, jsonify
from supabase import create_client, Client
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
import google.auth.transport.requests as grequests
import time # Added this import as it's used in your /process route

app = Flask(__name__, template_folder="templates")
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret")

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_ANON_KEY = os.environ["SUPABASE_ANON_KEY"]
supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

DAILY_LIMIT = 20

@app.route("/")
def home():
    return redirect("/dashboard")

@app.route("/dashboard")
def dashboard():
    user_id = request.args.get("user_id")
    if not user_id:
        return "Missing user_id", 401

    try:
        profile_resp = supabase.table("profiles") \
            .select("full_name, ai_enabled, email") \
            .eq("id", user_id) \
            .single() \
            .execute()

        profile = profile_resp.data
    except Exception as e:
        return f"Profile query error: {str(e)}", 500

    today = date.today().isoformat()
    sent_resp = supabase.table("emails") \
        .select("sent_at") \
        .eq("user_id", user_id) \
        .eq("status", "sent") \
        .execute()

    sent = sent_resp.data
    emails_sent_today = len([e for e in sent if e["sent_at"] and e["sent_at"].startswith(today)])
    time_saved = emails_sent_today * 5.5

    token_resp = supabase.table("gmail_tokens") \
        .select("credentials") \
        .eq("user_id", user_id) \
        .execute()

    token_data = token_resp.data
    show_reconnect = True
    if token_data:
        try:
            creds_data = token_data[0]["credentials"]
            creds = Credentials(
                token=creds_data["token"],
                refresh_token=creds_data["refresh_token"],
                token_uri=creds_data["token_uri"],
                client_id=creds_data["client_id"],
                client_secret=creds_data["client_secret"],
                user_email=creds_data["user_email"],
                scopes=creds_data["scopes"]
            )
            if not creds.expired:
                show_reconnect = False
        except Exception as e:
            print("Token check failed:", e)

    return render_template("dashboard.html",
        name=profile["full_name"],
        user_id=user_id,
        emails_sent=emails_sent_today,
        time_saved=time_saved,
        ai_enabled=profile.get("ai_enabled", True),
        show_reconnect=show_reconnect
    )

@app.route("/connect_gmail")
def connect_gmail():
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
                "openid"
            ]
        )
        flow.redirect_uri = os.environ["REDIRECT_URI"]
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials

        # Verify ID token to get email and user info
        id_info = id_token.verify_oauth2_token(
            credentials.id_token,
            grequests.Request(),
            os.environ["GOOGLE_CLIENT_ID"]
        )
        email = id_info.get("email")
        full_name = id_info.get("name") or email.split('@')[0]

        if not email:
            raise ValueError("No email found in Google ID token")

        # Use Supabase Admin API to find UUID by email
        auth_url = f"{SUPABASE_URL}/auth/v1/admin/users"
        headers = {
            "apikey": os.environ["SUPABASE_SERVICE_ROLE_KEY"],
            "Authorization": f"Bearer {os.environ['SUPABASE_SERVICE_ROLE_KEY']}"
        }
        resp = requests.get(auth_url, headers=headers, params={"email": email})

        if resp.status_code != 200:
            raise Exception(f"Supabase Admin API error: {resp.status_code} {resp.text}")

        users = resp.json().get("users", [])
        matching_users = [u for u in users if u["email"] == email]
        if not matching_users:
            raise Exception("User not found in Supabase Auth")

        user_id = matching_users[0]["id"]

        # Ensure profile exists
        profile_resp = supabase.table("profiles").select("id").eq("id", user_id).execute()
        if not profile_resp.data:
            supabase.table("profiles").insert({
                "id": user_id,
                "email": email,
                "full_name": full_name,
                "ai_enabled": True
            }).execute()

        # Store or update Gmail credentials
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

        return redirect(f"/dashboard?user_id={user_id}")

    except Exception as e:
        app.logger.error(f"OAuth2 Callback Error: {str(e)}", exc_info=True)
        return f"<h1>Authentication Failed</h1><p>{str(e)}</p>", 500


@app.route("/disconnect_gmail", methods=["POST"])
def disconnect_gmail():
    user_id = request.form.get("user_id")
    supabase.table("gmail_tokens").delete().eq("user_id", user_id).execute()
    return redirect(f"/dashboard?user_id={user_id}")

@app.route("/admin")
def admin():
    return render_template("admin.html")

@app.route("/api/admin/users")
def api_admin_users():
    users = supabase.table("profiles").select("*").execute().data
    today = date.today().isoformat()
    results = []

    for user in users:
        sent = supabase.table("emails") \
            .select("sent_at") \
            .eq("user_id", user["id"]) \
            .eq("status", "sent") \
            .execute().data

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
    supabase.table("profiles") \
        .update({"ai_enabled": enable}) \
        .eq("id", user_id) \
        .execute()
    return jsonify({"success": True})

@app.route("/debug_env")
def debug_env():
    return {
        "GOOGLE_CLIENT_ID": os.environ.get("GOOGLE_CLIENT_ID"),
        "REDIRECT_URI": os.environ.get("REDIRECT_URI")
    }

@app.route("/process")
def trigger_process():
    # 1) Token‐based auth
    token = request.args.get("token")
    PROCESS_TOKEN = os.environ.get("PROCESS_SECRET_TOKEN")
    if token != PROCESS_TOKEN:
        return "Unauthorized", 401

    # Base URL of your deployed Deno/Edge Function
    EDGE_BASE_URL = os.environ.get("EDGE_BASE_URL", "").rstrip("/")

    MAX_RETRIES = 5
    RETRY_BACKOFF_BASE = 2

    # Helper to call an Edge Function endpoint with retry on 429
    def call_edge(endpoint_path: str, payload: dict) -> bool:
        """
        endpoint_path is e.g. "/detect-jargon" or "/generate-response", etc.
        payload is the JSON body to post.
        Returns True if status_code == 200, False otherwise.
        """
        url = f"{EDGE_BASE_URL}{endpoint_path}"
        headers = {
            "Authorization": f"Bearer {os.environ['SUPABASE_SERVICE_ROLE_KEY']}",
            "apikey":        os.environ['SUPABASE_SERVICE_ROLE_KEY'],
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
        # If we exhaust all retries:
        app.logger.error(f"[{endpoint_path}] Exceeded max retries.")
        return False


    # We’ll collect all IDs we ever hand off to an Edge Function
    all_processed = []


    #### STAGE 1 → Detect Jargon
    # Look for any email with status = "awaiting_jargon".  For each one:
    #  a) Mark it → "processing" so that Edge Function sees it
    #  b) Call POST /detect-jargon with { "text": original_content }
    jargon_rows = supabase.table("emails") \
        .select("id, original_content") \
        .eq("status", "awaiting_jargon") \
        .execute().data or []

    if jargon_rows:
        jargon_ids = [r["id"] for r in jargon_rows]
        # Mark them processing
        supabase.table("emails") \
            .update({"status": "processing"}) \
            .in_("id", jargon_ids) \
            .execute()

        # Call the Edge Function _one at a time_, since it expects { "text": ... }
        # (If you want to batch, you could modify detect-jargon to accept email_ids instead of text,
        # but the code you gave expects a single "text" per request.)
        for row in jargon_rows:
            single_payload = { "text": row["original_content"] }
            success = call_edge("/detect-jargon", single_payload)
            if success:
                all_processed.append(row["id"])


    #### STAGE 2 → Generate Response
    # Next, any email whose status was (or became) "awaiting_response"
    resp_pending = supabase.table("emails") \
        .select("id") \
        .eq("status", "awaiting_response") \
        .execute().data or []

    if resp_pending:
        resp_ids = [r["id"] for r in resp_pending]
        # Mark them processing
        supabase.table("emails") \
            .update({"status": "processing"}) \
            .in_("id", resp_ids) \
            .execute()

        # Now call the Edge Function in one batch:
        payload = { "email_ids": resp_ids }
        success = call_edge("/generate-response", payload)
        if success:
            all_processed.extend(resp_ids)


    #### STAGE 3 → Personalize Template
    # Any email whose status is now "ready_to_personalize"
    # We assume each row has columns: template_text (string), past_emails (JSON array), deal_data (JSON object).
    per_pending = supabase.table("emails") \
        .select("id, template_text, past_emails, deal_data") \
        .eq("status", "ready_to_personalize") \
        .execute().data or []

    if per_pending:
        per_ids = [r["id"] for r in per_pending]
        # Mark processing
        supabase.table("emails") \
            .update({"status": "processing"}) \
            .in_("id", per_ids) \
            .execute()

        # We’ll send one request per email, because personalize-template expects those three fields
        for row in per_pending:
            template_text = row.get("template_text") or ""
            past_emails   = row.get("past_emails") or []
            deal_data     = row.get("deal_data") or {}

            payload = {
                "template_text": template_text,
                "past_emails":   past_emails,
                "deal_data":     deal_data
            }
            success = call_edge("/personalize-template", payload)
            if success:
                all_processed.append(row["id"])


    #### STAGE 4 → Generate Proposal
    # Any email whose status is "awaiting_proposal"
    prop_pending = supabase.table("emails") \
        .select("id, market, deal_type, cap_rate, tenant_type, style") \
        .eq("status", "awaiting_proposal") \
        .execute().data or []

    if prop_pending:
        prop_ids = [r["id"] for r in prop_pending]
        # Mark processing
        supabase.table("emails") \
            .update({"status": "processing"}) \
            .in_("id", prop_ids) \
            .execute()

        # One request per email (since generate-proposal needs those five fields)
        for row in prop_pending:
            payload = {
                "market":      row.get("market"),
                "deal_type":   row.get("deal_type"),
                "cap_rate":    row.get("cap_rate"),
                "tenant_type": row.get("tenant_type"),
                "style":       row.get("style")
            }
            success = call_edge("/generate-proposal", payload)
            if success:
                all_processed.append(row["id"])


    #### STAGE 5 → Send Emails via Gmail
    # Finally, anything that ended up with status = "ready_to_send" should be mailed
    sent, failed = [], []
    ready_list = supabase.table("emails") \
        .select("id, user_id, sender_email, processed_content") \
        .eq("status", "ready_to_send") \
        .execute().data or []

    for row in ready_list:
        em_id = row["id"]
        uid   = row["user_id"]
        to    = row["sender_email"]
        body  = row["processed_content"] or ""

        # Fetch OAuth token for this user
        tok_rows = supabase.table("gmail_tokens") \
            .select("credentials") \
            .eq("user_id", uid) \
            .limit(1) \
            .execute().data

        if not tok_rows:
            app.logger.warning(f"No Gmail token for user {uid}, skipping email {em_id}")
            failed.append(em_id)
            continue

        creds_data = tok_rows[0]["credentials"]
        creds = Credentials(
            token=creds_data["token"],
            refresh_token=creds_data["refresh_token"],
            token_uri=creds_data["token_uri"],
            client_id=creds_data["client_id"],
            client_secret=creds_data["client_secret"],
            scopes=creds_data["scopes"]
        )
        # Refresh if needed
        if creds.expired and creds.refresh_token:
            creds.refresh(GoogleRequest())

        try:
            svc = build("gmail", "v1", credentials=creds, cache_discovery=False)
            msg = MIMEText(body, "plain")
            msg["to"]      = to
            msg["from"]    = "me"
            msg["subject"] = "Re: your email"
            raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()

            send_res = svc.users().messages().send(userId="me", body={"raw": raw}).execute()

            # Mark as sent
            supabase.table("emails").update({
                "status":  "sent",
                "sent_at": datetime.utcnow().isoformat()
            }).eq("id", em_id).execute()

            sent.append(em_id)
            app.logger.info(f"Sent email {em_id} → Gmail message ID {send_res.get('id')}")
        except Exception as e:
            failed.append(em_id)
            app.logger.error(f"Send failed for {em_id}: {e}", exc_info=True)

    # Return a summary
    return jsonify({
        "processed": all_processed,
        "sent":      sent,
        "failed":    failed,
        "summary":   f"{len(sent)} sent, {len(failed)} failed, {len(all_processed)} processed through Edge Fn"
    }), 200


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 10000)))
