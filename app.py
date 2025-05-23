import os
import json
from flask import Flask, render_template, request, redirect, jsonify
from datetime import date
from supabase import create_client, Client
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
import google.auth.transport.requests as grequests

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

    today = date.today().isoformat()
    sent = supabase.table("emails").select("sent_at").eq("user_id", user_id).eq("status", "sent").execute().data
    emails_sent_today = len([e for e in sent if e["sent_at"] and e["sent_at"].startswith(today)])
    time_saved = emails_sent_today * 3

    # Fetch user profile
    try:
        profile_resp = supabase.table("profiles").select("full_name, ai_enabled").eq("id", user_id).limit(1).execute()
        if not profile_resp.data:
            return f"User {user_id} not found in profiles table", 404
        profile = profile_resp.data[0]
    except Exception as e:
        return f"Profile query error: {str(e)}", 500

    # Check if Gmail token is expired
    token_resp = supabase.table("gmail_tokens").select("credentials").eq("user_email", user_id).execute().data
    show_reconnect = True

    if token_resp:
        try:
            creds_data = token_resp[0]["credentials"]
            creds = Credentials(
                token=creds_data["token"],
                refresh_token=creds_data["refresh_token"],
                token_uri=creds_data["token_uri"],
                client_id=creds_data["client_id"],
                client_secret=creds_data["client_secret"],
                scopes=creds_data["scopes"]
            )

            if creds.expired:
                creds.refresh(Request())

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
    flow = Flow.from_client_config({
        "web": {
            "client_id": os.environ["GOOGLE_CLIENT_ID"],
            "client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [os.environ["REDIRECT_URI"]],
        }
    },
    scopes=[
        "https://www.googleapis.com/auth/gmail.send",
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/userinfo.email",
        "openid"
    ])
    flow.redirect_uri = os.environ["REDIRECT_URI"]

    authorization_url, _ = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent"
    )
    return redirect(authorization_url)

@app.route("/oauth2callback")
def oauth2callback():
    flow = Flow.from_client_config({
        "web": {
            "client_id": os.environ["GOOGLE_CLIENT_ID"],
            "client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [os.environ["REDIRECT_URI"]],
        }
    },
    scopes=[
        "https://www.googleapis.com/auth/gmail.send",
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/userinfo.email",
        "openid"
    ])
    flow.redirect_uri = os.environ["REDIRECT_URI"]
    flow.fetch_token(authorization_response=request.url)

    credentials = flow.credentials
    info = id_token.verify_oauth2_token(
        credentials.id_token,
        grequests.Request(),
        os.environ["GOOGLE_CLIENT_ID"]
    )
    email = info["email"]

    # Store Gmail tokens
    supabase.table("gmail_tokens").upsert({
        "user_email": email,
        "credentials": {
            "token": credentials.token,
            "refresh_token": credentials.refresh_token,
            "token_uri": credentials.token_uri,
            "client_id": credentials.client_id,
            "client_secret": credentials.client_secret,
            "scopes": credentials.scopes
        }
    }).execute()

    # Create user profile if missing
    existing = supabase.table("profiles").select("id").eq("id", email).execute().data
    if not existing:
        supabase.table("profiles").insert({
            "id": email,
            "full_name": email.split("@")[0].title(),
            "ai_enabled": True
        }).execute()

    return redirect(f"/dashboard?user_id={email}")


@app.route("/disconnect_gmail", methods=["POST"])
def disconnect_gmail():
    user_id = request.form.get("user_id")
    supabase.table("gmail_tokens").delete().eq("user_email", user_id).execute()
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

if __name__ == "__main__":
    app.run(debug=True)
