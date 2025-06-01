import base64
import os
import json
import time
import requests
from datetime import date, datetime
from email.mime.text import MIMEText
from flask import Flask, render_template, request, redirect, jsonify
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
import google.auth.transport.requests as grequests
from googleapiclient.discovery import build
from supabase import create_client, Client

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
        profile_resp = supabase.table("profiles").select("full_name, ai_enabled, email").eq("id", user_id).single().execute()
        profile = profile_resp.data
    except Exception as e:
        return f"Profile query error: {str(e)}", 500

    today = date.today().isoformat()
    sent_resp = supabase.table("emails").select("sent_at").eq("user_id", user_id).eq("status", "sent").execute()
    sent = sent_resp.data
    emails_sent_today = len([e for e in sent if e["sent_at"] and e["sent_at"].startswith(today)])
    time_saved = emails_sent_today * 5.5

    token_resp = supabase.table("gmail_tokens").select("credentials").eq("user_id", user_id).execute()
    token_data = token_resp.data
    show_reconnect = True

    if token_data:
        try:
            creds_data = token_data[0]["credentials"]
            creds = Credentials(
                token=creds_data["token"],
                refresh_token=creds_data.get("refresh_token"),
                token_uri=creds_data["token_uri"],
                client_id=creds_data["client_id"],
                client_secret=creds_data["client_secret"],
                scopes=creds_data["scopes"]
            )
            if not creds.expired or (creds.refresh_token and creds.valid):
                show_reconnect = False
        except Exception as e:
            app.logger.error("Token check failed: %s", str(e))

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

        id_info = id_token.verify_oauth2_token(
            credentials.id_token,
            grequests.Request(),
            os.environ["GOOGLE_CLIENT_ID"]
        )
        email = id_info.get("email")
        if not email:
            raise ValueError("No email found in Google response")

        # Use Supabase Auth to get consistent UUID
        try:
            # Check if user exists
            auth_response = supabase.auth.sign_in_with_id_token({
                "provider": "google",
                "id_token": credentials.id_token
            })
            user_id = auth_response.user.id
        except Exception as auth_error:
            # Create new user if doesn't exist
            auth_response = supabase.auth.sign_up({
                "email": email,
                "password": os.urandom(16).hex(),  # Random password
                "options": {
                    "data": {
                        "full_name": id_info.get("name") or email.split('@')[0]
                    }
                }
            })
            if auth_response.user:
                user_id = auth_response.user.id
            else:
                raise RuntimeError("User creation failed") from auth_error

        # Create/update profile with same UUID
        profile_data = {
            "id": user_id,
            "email": email,
            "full_name": id_info.get("name") or email.split('@')[0],
            "ai_enabled": True
        }
        supabase.table("profiles").upsert(profile_data).execute()

        # Store token with same UUID
        token_payload = {
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
        supabase.table("gmail_tokens").upsert(token_payload).execute()
        return redirect(f"/dashboard?user_id={user_id}")

    except Exception as e:
        app.logger.error(f"OAuth Error: {str(e)}", exc_info=True)
        return f"<h1>Authentication Failed</h1><p>{str(e)}</p>", 500

@app.route("/disconnect_gmail", methods=["POST"])
def disconnect_gmail():
    user_id = request.form.get("user_id")
    supabase.table("gmail_tokens").delete().eq("user_id", user_id).execute()
    return redirect(f"/dashboard?user_id={user_id}")

@app.route("/process")
def trigger_process():
    token = request.args.get("token")
    if token != os.environ.get("PROCESS_SECRET_TOKEN"):
        return "Unauthorized", 401

    pre = supabase.table("emails").select("id").eq("status", "preprocessing").execute()
    email_ids = [r["id"] for r in pre.data]
    if not email_ids:
        return "No emails to process", 204

    supabase.table("emails").update({"status": "processing"}).in_("id", email_ids).execute()

    edge_url = "https://skxzfkudduqrubtgtodp.functions.supabase.co/generate-response"
    MAX_RETRIES = 5
    RETRY_BACKOFF_BASE = 2

    for attempt in range(MAX_RETRIES):
        try:
            resp = requests.post(
                edge_url,
                json={"email_ids": email_ids},
                headers={
                    "Authorization": f"Bearer {os.environ['SUPABASE_SERVICE_ROLE_KEY']}",
                    "apikey":        os.environ['SUPABASE_SERVICE_ROLE_KEY'],
                    "Content-Type":  "application/json"
                },
                timeout=60
            )

            if resp.status_code == 200:
                break
            elif resp.status_code == 429:
                wait = RETRY_BACKOFF_BASE ** attempt
                app.logger.warning(f"[Retry {attempt+1}/{MAX_RETRIES}] Hugging Face rate-limited. Waiting {wait}s...")
                time.sleep(wait)
            else:
                app.logger.error("Edge function failed (%s): %s", resp.status_code, resp.text)
                return f"Edge function error {resp.status_code}", 500
        except requests.RequestException as e:
            wait = RETRY_BACKOFF_BASE ** attempt
            app.logger.error(f"[Retry {attempt+1}/{MAX_RETRIES}] Edge call exception: {e}. Retrying in {wait}s...")
            time.sleep(wait)
    else:
        return "Exceeded max retries calling Edge function", 429

    sent, failed = [], []
    ready = supabase.table("emails").select("id,user_id,sender_email,processed_content").eq("status", "ready_to_send").execute().data

    for row in ready:
        em_id = row["id"]
        uid = row["user_id"]
        to = row["sender_email"]
        body = row["processed_content"] or ""

        tok_rows = supabase.table("gmail_tokens").select("credentials").eq("user_id", uid).limit(1).execute().data
        if not tok_rows:
            app.logger.warning("No Gmail token for user %s, skipping %s", uid, em_id)
            failed.append(em_id)
            continue

        creds_data = tok_rows[0]["credentials"]
        creds = Credentials(
            token=creds_data["token"],
            refresh_token=creds_data.get("refresh_token"),
            token_uri=creds_data["token_uri"],
            client_id=creds_data["client_id"],
            client_secret=creds_data["client_secret"],
            scopes=creds_data["scopes"]
        )

        try:
            if creds.expired and creds.refresh_token:
                creds.refresh(GoogleRequest())

            svc = build("gmail", "v1", credentials=creds, cache_discovery=False)
            msg = MIMEText(body, "plain")
            msg["to"] = to
            msg["from"] = "me"
            msg["subject"] = "Re: your email"
            raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()

            svc.users().messages().send(userId="me", body={"raw": raw}).execute()

            supabase.table("emails").update({
                "status": "sent",
                "sent_at": datetime.utcnow().isoformat()
            }).eq("id", em_id).execute()

            sent.append(em_id)
        except Exception as e:
            app.logger.error("Failed to send %s: %s", em_id, e)
            failed.append(em_id)

    return jsonify({"sent": sent, "failed": failed})

# Admin API
@app.route("/admin")
def admin():
    return render_template("admin.html")

@app.route("/api/admin/users")
def api_admin_users():
    users = supabase.table("profiles").select("*").execute().data
    today = date.today().isoformat()
    results = []

    for user in users:
        sent = supabase.table("emails").select("sent_at").eq("user_id", user["id"]).eq("status", "sent").execute().data
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
        "REDIRECT_URI": os.environ.get("REDIRECT_URI")
    }
