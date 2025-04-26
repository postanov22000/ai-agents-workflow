import requests
import os
import time
import base64
from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

# ── Configuration from environment ──────────────────────────────
SUPABASE_URL              = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
GMAIL_CREDENTIALS_FILE    = 'credentials.json'   # must be "installed"-type JSON
TOKEN_FILE                = 'token.json'
SCOPES                    = ['https://www.googleapis.com/auth/gmail.send']

# ── Gmail OAuth / Credential helpers ────────────────────────────
def authenticate_gmail():
    creds = None
    # 1) Try load saved credentials
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    # 2) If missing or expired, do manual flow
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(GMAIL_CREDENTIALS_FILE, SCOPES)
            auth_url, _ = flow.authorization_url(prompt='consent')
            print("\n👉 Go to this URL in your browser:\n", auth_url, "\n")
            code = input("Enter the authorization code here: ")
            flow.fetch_token(code=code)
            creds = flow.credentials
        # save for next time
        with open(TOKEN_FILE, 'w') as f:
            f.write(creds.to_json())
    return creds

def build_gmail_service():
    creds = authenticate_gmail()
    return build('gmail','v1',credentials=creds)

# ── Email creation & sending ────────────────────────────────────
def create_message(sender, to, subject, body):
    raw = base64.urlsafe_b64encode(
        f"From: {sender}\r\nTo: {to}\r\nSubject: {subject}\r\n\r\n{body}".encode()
    ).decode()
    return {'raw': raw}

def send_email_via_gmail(email):
    svc = build_gmail_service()
    msg = create_message(
        email['sender_email'],
        email['recipient_email'],
        email.get('subject','(no subject)'),
        email.get('ai_response','')
    )
    try:
        sent = svc.users().messages().send(userId='me', body=msg).execute()
        print("Sent:", sent['id'])
    except Exception as e:
        print("Send error:", e)

# ── Supabase update ─────────────────────────────────────────────
def mark_email_complete(email_id):
    h = {
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "apikey":       SUPABASE_SERVICE_ROLE_KEY,
        "Content-Type": "application/json",
    }
    r = requests.patch(
        f"{SUPABASE_URL}/rest/v1/emails?id=eq.{email_id}",
        json={"status":"complete"},
        headers=h
    )
    print("Mark status:", r.status_code, r.text if r.status_code>=300 else "")

# ── Polling loop ────────────────────────────────────────────────
def poll_sent_emails():
    h = {
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "apikey":       SUPABASE_SERVICE_ROLE_KEY,
        "Content-Type": "application/json",
    }
    while True:
        r = requests.get(f"{SUPABASE_URL}/rest/v1/emails?status=eq.sent", headers=h)
        if r.status_code != 200:
            print("Fetch error:", r.status_code, r.text)
            time.sleep(30)
            continue
        emails = r.json()
        print(f"⏱️ Found {len(emails)} emails with status=sent")
        for e in emails:
            send_email_via_gmail(e)
            mark_email_complete(e['id'])
        time.sleep(30)

if __name__=="__main__":
    poll_sent_emails()
