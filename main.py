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

    try:
        profile = supabase.table("profiles") \
            .select("full_name, ai_enabled, email") \
            .eq("id", user_id) \
            .single() \
            .execute().data
    except Exception as e:
        return f"Profile error: {e}", 500

    today = date.today().isoformat()
    sent_today = supabase.table("emails") \
        .select("sent_at") \
        .eq("user_id", user_id) \
        .eq("status", "sent") \
        .execute().data

    emails_sent_today = len([e for e in sent_today if e["sent_at"] and e["sent_at"].startswith(today)])
    time_saved = emails_sent_today * 5.5

    # Gmail token status
    tokens = supabase.table("gmail_tokens").select("credentials").eq("user_id", user_id).execute().data
    show_reconnect = True
    if tokens:
        try:
            creds_data = tokens[0]["credentials"]
            creds = Credentials(
                token=creds_data["token"],
                refresh_token=creds_data["refresh_token"],
                token_uri=creds_data["token_uri"],
                client_id=creds_data["client_id"],
                client_secret=creds_data["client_secret"],
                scopes=creds_data["scopes"]
            )
            if creds and not creds.expired:
                show_reconnect = False
        except Exception as e:
            print("Token check failed:", e)

    return render_template("dashboard.html",
                           name=profile["full_name"],
                           user_id=user_id,
                           emails_sent=emails_sent_today,
                           time_saved=time_saved,
                           ai_enabled=profile.get("ai_enabled", True),
                           show_reconnect=show_reconnect)


@app.route("/connect_gmail")
def connect_gmail():
    flow = Flow.from_client_config(
        {
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
        ]
    )
    flow.redirect_uri = os.environ["REDIRECT_URI"]
    authorization_url, _ = flow.authorization_url(
        access_type="offline",
        prompt="consent",
        include_granted_scopes="true"
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
                    "redirect_uris": [os.environ["REDIRECT_URI"]],
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
            raise ValueError("No email found in ID token")

        # Lookup or create profile
        profile = supabase.table("profiles").select("id").eq("email", email).execute().data
        if not profile:
            new_profile = supabase.table("profiles").insert({
                "email": email,
                "full_name": id_info.get("name") or email.split("@")[0],
                "ai_enabled": True
            }).execute().data
            user_id = new_profile[0]["id"]
        else:
            user_id = profile[0]["id"]

        # Upsert credentials
        supabase.table("gmail_tokens").upsert({
            "user_id": user_id,
            "credentials": {
                "token": credentials.token,
                "refresh_token": credentials.refresh_token,
                "token_uri": credentials.token_uri,
                "client_id": credentials.client_id,
                "client_secret": credentials.client_secret,
                "scopes": credentials.scopes,
            }
        }).execute()

        return redirect(f"/dashboard?user_id={user_id}")

    except Exception as e:
        app.logger.error(f"OAuth2 callback failed: {e}", exc_info=True)
        return f"<h1>Authentication failed</h1><p>{str(e)}</p>", 500


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
    today = date.today().isoformat()
    users = supabase.table("profiles").select("*").execute().data
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
    supabase.table("profiles").update({"ai_enabled": enable}).eq("id", user_id).execute()
    return jsonify({"success": True})


@app.route("/debug_env")
def debug_env():
    return {
        "GOOGLE_CLIENT_ID": os.environ.get("GOOGLE_CLIENT_ID"),
        "REDIRECT_URI": os.environ.get("REDIRECT_URI")
    }


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
