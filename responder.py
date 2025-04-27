import os
import time
import base64
import threading
import logging
import requests

from flask import Flask
from waitress import serve
from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

# ── Configuration ──────────────────────────────────────────────────────────────
SUPABASE_URL              = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
GMAIL_CREDENTIALS_FILE    = "credentials.json"
TOKEN_FILE                = "token.json"
SCOPES                    = ["https://www.googleapis.com/auth/gmail.send"]
POLL_INTERVAL_SECONDS     = 30

# ── Logging setup ───────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# ── Flask health + index ────────────────────────────────────────────────────────
app = Flask(__name__)

@app.route("/")
def index():
    return "Responder is running", 200

@app.route("/health")
def health():
    return "OK", 200

def run_health_server():
    serve(app, host="0.0.0.0", port=3000)

# ── Gmail OAuth ─────────────────────────────────────────────────────────────────
def authenticate_gmail():
    creds = None
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(GMAIL_CREDENTIALS_FILE, SCOPES)
            flow.redirect_uri = 'urn:ietf:wg:oauth:2.0:oob'
            auth_url, _ = flow.authorization_url(prompt='consent')
            print("\n👉 Go to authorize:", auth_url)
            code = input("Enter the authorization code: ")
            flow.fetch_token(code=code)
            creds = flow.credentials
        with open(TOKEN_FILE, "w") as token:
            token.write(creds.to_json())
    return creds

def build_gmail_service():
    creds = authenticate_gmail()
    return build("gmail", "v1", credentials=creds)

# ── Email creation & sending ───────────────────────────────────────────────────
def create_message(sender, to, subject, body):
    raw = base64.urlsafe_b64encode(
        f"From: {sender}\r\nTo: {to}\r\nSubject: {subject}\r\n\r\n{body}".encode()
    ).decode()
    return {"raw": raw}

def send_email_via_gmail(email):
    svc = build_gmail_service()
    msg = create_message(
        email["sender_email"],
        email["recipient_email"],
        email.get("subject", "(no subject)"),
        email.get("ai_response", "")
    )
    try:
        out = svc.users().messages().send(userId="me", body=msg).execute()
        logger.info(f"✅ Sent email id={email['id']} gmail_id={out['id']}")
    except Exception as ex:
        logger.error(f"❌ Send error for email id={email['id']}: {ex}")

# ── Supabase update ────────────────────────────────────────────────────────────
def mark_email_complete(email_id):
    headers = {
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Content-Type": "application/json",
    }
    r = requests.patch(
        f"{SUPABASE_URL}/rest/v1/emails?id=eq.{email_id}",
        json={"status": "complete"},
        headers=headers
    )
    if r.status_code in (200, 204):
        logger.info(f"✅ Marked complete id={email_id}")
    else:
        logger.error(f"❌ Failed to mark complete id={email_id}: {r.status_code} {r.text}")

# ── Polling loop ────────────────────────────────────────────────────────────────
def poll_sent_emails():
    headers = {
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Content-Type": "application/json",
    }
    while True:
        r = requests.get(f"{SUPABASE_URL}/rest/v1/emails?status=eq.sent", headers=headers)
        if r.status_code != 200:
            logger.error(f"Fetch error: {r.status_code} {r.text}")
            time.sleep(POLL_INTERVAL_SECONDS)
            continue
        emails = r.json()
        logger.info(f"⏱️ Found {len(emails)} emails with status=sent")
        for email in emails:
            send_email_via_gmail(email)
            mark_email_complete(email["id"])
        time.sleep(POLL_INTERVAL_SECONDS)

# ── Entry point ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    threading.Thread(target=run_health_server, daemon=True).start()
    poll_sent_emails()
