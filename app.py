import os
import json
import logging
import hashlib
from flask import Flask, render_template, request, redirect, jsonify, session
from datetime import date
from supabase import create_client, Client
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from werkzeug.exceptions import HTTPException

# Absolute template path fix
template_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
app = Flask(__name__, template_folder=template_path)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24))

# Supabase
SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_ANON_KEY = os.environ["SUPABASE_ANON_KEY"]
SUPABASE_SERVICE_ROLE_KEY = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

# Google OAuth config
SCOPES = [
    "https://www.googleapis.com/auth/userinfo.email",
    "openid",
    "https://www.googleapis.com/auth/gmail.send"
]
CLIENT_SECRETS_FILE = "client_secrets.json"
REDIRECT_URI = "https://replyzeai.onrender.com/oauth2callback"

# Ensure secrets file exists
def validate_client_secrets():
    if not os.path.exists(CLIENT_SECRETS_FILE):
        client_secrets = os.environ.get("GOOGLE_CLIENT_SECRETS")
        if client_secrets:
            with open(CLIENT_SECRETS_FILE, "w") as f:
                f.write(client_secrets)
        else:
            raise RuntimeError("Missing GOOGLE_CLIENT_SECRETS")

validate_client_secrets()

DAILY_LIMIT = 20

@app.errorhandler(Exception)
def handle_exception(e):
    logging.exception("Unexpected error")
    return "Internal Server Error", 500

@app.route("/")
def home():
    return redirect("/dashboard")

@app.route("/dashboard")
def dashboard():
    user_id = request.args.get("user_id")
    if not user_id:
        return "Missing user_id", 401

    today = date.today().isoformat()
    sent = supabase.table("emails").select("sent_at").eq("user_id", user_id).eq("status", "sent").execute().data
    count = len([e for e in sent if e["sent_at"] and e["sent_at"].startswith(today)])
    time_saved = count * 3

    profile = supabase.table("profiles").select("full_name, ai_enabled").eq("id", user_id).single().execute().data
    return render_template("dashboard.html",
        name=profile["full_name"],
        user_id=user_id,
        emails_sent=count,
        time_saved=time_saved,
        ai_enabled=profile.get("ai_enabled", True)
    )

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
        sent = supabase.table("emails").select("sent_at").eq("user_id", user["id"]).eq("status", "sent").execute().data
        count = len([e for e in sent if e["sent_at"] and e["sent_at"].startswith(today)])
        results.append({
            "id": user["id"],
            "name": user["full_name"],
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

# Gmail OAuth flow
@app.route("/authorize")
def authorize():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    auth_url, state = flow.authorization_url(
        access_type="offline",
        prompt="consent",
        include_granted_scopes="false"
    )
    session["state"] = state
    return redirect(auth_url)

@app.route("/oauth2callback")
def oauth2callback():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=session.get("state"),
        redirect_uri=REDIRECT_URI
    )
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials

    user_info_service = build("oauth2", "v2", credentials=credentials)
    user_info = user_info_service.userinfo().get().execute()
    user_email = user_info.get("email")

    credentials_data = {
        "token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "token_uri": credentials.token_uri,
        "client_id": credentials.client_id,
        "client_secret": credentials.client_secret,
        "scopes": credentials.scopes
    }

    supabase.table("gmail_tokens").upsert({
        "user_email": user_email,
        "credentials": credentials_data
    }).execute()

    return f"✅ Gmail connected for {user_email}"

# Process endpoint for GitHub Actions / Cron
@app.route("/process", methods=["GET"])
def process_emails():
    token = request.args.get("token")
    if not token or token != os.environ.get("PROCESS_SECRET_TOKEN"):
        return "Unauthorized", 401

    from main import run_worker
    result = run_worker()
    return f"Processed: {result}", 200

if __name__ == "__main__":
    app.run(debug=True)
