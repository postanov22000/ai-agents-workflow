import os
import json
import time
import hashlib
import pickle
import threading
import requests
from flask import Flask, redirect, request
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from supabase import create_client, Client

# Flask app
app = Flask(__name__)

# Gmail OAuth config
CLIENT_SECRETS_FILE = "client_secrets.json"
SCOPES = ["https://www.googleapis.com/auth/gmail.send", "https://www.googleapis.com/auth/userinfo.email", "openid"]
REDIRECT_URI = "https://replyzeai.onrender.com/oauth2callback"

# Supabase config
SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Helper to load Gmail credentials
def load_credentials(email):
    path = os.path.join("tokens", hashlib.sha256(email.encode()).hexdigest() + ".pickle")
    if not os.path.exists(path):
        return None
    with open(path, "rb") as token:
        creds = pickle.load(token)
    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        with open(path, "wb") as token:
            pickle.dump(creds, token)
    return creds

# Worker function
def run_worker():
    while True:
        try:
            res = supabase.table("emails").select("*").eq("status", "ready_to_send").execute()
            emails = res.data
            if emails:
                print(f"Found {len(emails)} emails to send.")
            for email in emails:
                try:
                    to = email["to"]
                    body = email["processed_content"]
                    sender = email["sender_email"]
                    creds = load_credentials(sender)
                    if not creds:
                        raise Exception(f"No token for {sender}")

                    service = build("gmail", "v1", credentials=creds)
                    message = {
                        "raw": create_raw_email(to, sender, body)
                    }
                    service.users().messages().send(userId="me", body=message).execute()

                    supabase.table("emails").update({
                        "status": "sent",
                        "sent_at": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
                    }).eq("id", email["id"]).execute()
                except Exception as e:
                    print("Error sending email:", e)
                    supabase.table("emails").update({"status": "failed"}).eq("id", email["id"]).execute()

        except Exception as e:
            print("Worker error:", e)
        time.sleep(30)  # Check every 30 seconds

# Helper to build raw email
import base64
from email.mime.text import MIMEText
def create_raw_email(to, sender, message_text):
    message = MIMEText(message_text)
    message["to"] = to
    message["from"] = sender
    message["subject"] = "Re: Your Inquiry"
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    return raw

# Flask Routes

@app.route("/")
def index():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
    )
    auth_url, _ = flow.authorization_url(prompt="consent", access_type="offline", include_granted_scopes="true")
    return redirect(auth_url)

@app.route("/oauth2callback")
def oauth2callback():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
    )
    flow.fetch_token(authorization_response=request.url)

    credentials = flow.credentials
    service = build("gmail", "v1", credentials=credentials)
    profile = service.users().getProfile(userId="me").execute()
    user_email = profile["emailAddress"]

    os.makedirs("tokens", exist_ok=True)
    filename = os.path.join("tokens", hashlib.sha256(user_email.encode()).hexdigest() + ".pickle")
    with open(filename, "wb") as token:
        pickle.dump(credentials, token)

    return f"Gmail connected successfully for {user_email}!"

# Start the worker in a background thread when the app starts
@app.before_first_request
def start_worker():
    thread = threading.Thread(target=run_worker)
    thread.daemon = True
    thread.start()

if __name__ == "__main__":
    app.run(debug=True)
