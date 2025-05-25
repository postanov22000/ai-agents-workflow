import base64
import os
import json
import requests
from google.auth.transport.requests import Request as GoogleRequest
from datetime import datetime
from email.mime.text import MIMEText
from flask import abort
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
    time_saved = emails_sent_today * 3

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

        id_info = id_token.verify_oauth2_token(
            credentials.id_token,
            grequests.Request(),
            os.environ["GOOGLE_CLIENT_ID"]
        )

        email = id_info.get("email")
        if not email:
            raise ValueError("No email found in Google response")

        profile_resp = supabase.table("profiles") \
            .select("id") \
            .eq("email", email) \
            .execute()

        profile_data = profile_resp.data

        if not profile_data:
            new_profile_resp = supabase.table("profiles").insert({
                "email": email,
                "full_name": id_info.get("name") or email.split('@')[0],
                "ai_enabled": True
            }).execute()

            new_profile = new_profile_resp.data
            if not new_profile:
                raise ValueError("Failed to create new profile")
            user_id = new_profile[0]['id']
        else:
            user_id = profile_data[0]['id']

        token_payload = {
            "user_id": user_id,
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
    # 1) Authenticate
    token = request.args.get("token", "")
    if token != os.environ.get("PROCESS_SECRET_TOKEN"):
        return "Unauthorized", 401

    # 2) Generate AI replies
    try:
        pre = supabase.table("emails") \
            .select("id") \
            .eq("status", "preprocessing") \
            .execute()
        pre_ids = [row["id"] for row in pre.data]
    except Exception as e:
        app.logger.error("Failed fetching preprocessing emails: %s", e, exc_info=True)
        return "DB error", 500

    if pre_ids:
        # mark as processing
        supabase.table("emails") \
            .update({"status": "processing"}) \
            .in_("id", pre_ids) \
            .execute()

        # build edge URL from your SUPABASE_URL
        project_ref = SUPABASE_URL.split("https://",1)[1].split(".",1)[0]
        edge_url    = f"https://skxzfkudduqrubtgtodp.functions.supabase.co/generate-response"

        edge_resp = requests.post(
            edge_url,
            json={"email_ids": pre_ids},
            headers={"Authorization": f"Bearer {os.environ['SUPABASE_SERVICE_ROLE_KEY']}"},
            timeout=60
        )
        if edge_resp.status_code != 200:
            app.logger.error("Edge function failed (%s): %s", edge_resp.status_code, edge_resp.text)
            return "Edge error", 500

    # 3) Send out replies
    try:
        ready = supabase.table("emails") \
            .select("id, user_id, recipient_email, subject, processed_content") \
            .eq("status", "ready_to_send") \
            .execute().data
    except Exception as e:
        app.logger.error("Failed fetching ready_to_send emails: %s", e, exc_info=True)
        return "DB error", 500

    sent_ids = []
    for row in ready:
        em_id    = row["id"]
        user_id  = row["user_id"]
        to_email = row["recipient_email"]
        subj     = row["subject"]
        body     = row["processed_content"] or ""

        # load & refresh Gmail creds
        creds_data = supabase.table("gmail_tokens") \
            .select("credentials") \
            .eq("user_id", user_id) \
            .single().execute().data["credentials"]

        creds = Credentials(
            token=creds_data["token"],
            refresh_token=creds_data["refresh_token"],
            token_uri=creds_data["token_uri"],
            client_id=creds_data["client_id"],
            client_secret=creds_data["client_secret"],
            scopes=creds_data["scopes"]
        )
        if not creds.valid:
            creds.refresh(GoogleRequest())
            supabase.table("gmail_tokens").upsert({
                "user_id": user_id,
                "credentials": {
                    "token": creds.token,
                    "refresh_token": creds.refresh_token,
                    "token_uri": creds.token_uri,
                    "client_id": creds.client_id,
                    "client_secret": creds.client_secret,
                    "scopes": creds.scopes
                }
            }).execute()

        # create message
        msg = MIMEText(body, "plain", "utf-8")
        msg["To"]      = to_email
        msg["Subject"] = f"Re: {subj}"
        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()

        send_resp = requests.post(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
            headers={
                "Authorization": f"Bearer {creds.token}",
                "Content-Type":  "application/json"
            },
            json={"raw": raw},
            timeout=30
        )
        if send_resp.status_code == 200:
            sent_ids.append(em_id)
            supabase.table("emails") \
                .update({
                    "status": "sent",
                    "sent_at": datetime.utcnow().isoformat()
                }) \
                .eq("id", em_id).execute()
        else:
            app.logger.error("Failed to send email %s: %s", em_id, send_resp.text)

    return jsonify({
        "generated": len(pre_ids),
        "sent":      len(sent_ids),
        "sent_ids":  sent_ids
    }), 200



if __name__ == "__main__":
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 10000)))
