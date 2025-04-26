import requests
import os
import time
import base64
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request

# Load environment variables
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
GMAIL_CREDENTIALS_FILE = 'credentials.json'   # keep this out of GitHub
SCOPES = ['https://www.googleapis.com/auth/gmail.send']

# Poll Supabase for emails with status 'sent'
def poll_sent_emails():
    headers = {
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "apikey": SUPABASE_SERVICE_ROLE_KEY,           # ← must include
        "Content-Type": "application/json",
    }
    while True:
        resp = requests.get(
            f"{SUPABASE_URL}/rest/v1/emails?status=eq.sent",
            headers=headers
        )
        if resp.status_code != 200:
            print("Error fetching emails:", resp.text)
            time.sleep(30)
            continue

        for email in resp.json():
            send_email_via_gmail(email)
            mark_email_complete(email['id'])

        time.sleep(30)

# Gmail OAuth flow
def authenticate_gmail():
    creds = None
    if os.path.exists('token.json'):
        creds = Request().from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(GMAIL_CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.json','w') as t:
            t.write(creds.to_json())
    return creds

# Build Gmail service
def build_gmail_service():
    creds = authenticate_gmail()
    return build('gmail','v1',credentials=creds)

# Create & send email
def create_message(sender, to, subject, body):
    raw = base64.urlsafe_b64encode(
        f"From: {sender}\r\nTo: {to}\r\nSubject: {subject}\r\n\r\n{body}".encode()
    ).decode()
    return {'raw': raw}

def send_email_via_gmail(email):
    service = build_gmail_service()
    msg = create_message(
        email['sender_email'],
        email['recipient_email'],
        email.get('subject','(no subject)'),
        email.get('ai_response','')
    )
    try:
        sent = service.users().messages().send(userId='me', body=msg).execute()
        print("Sent:", sent['id'])
    except Exception as e:
        print("Send error:", e)

# Mark complete in Supabase
def mark_email_complete(email_id):
    headers = {
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "apikey": SUPABASE_SERVICE_ROLE_KEY,           # ← must include
        "Content-Type": "application/json",
    }
    resp = requests.patch(
        f"{SUPABASE_URL}/rest/v1/emails?id=eq.{email_id}",
        json={"status":"complete"},
        headers=headers
    )
    if resp.status_code in (200,204):
        print(f"Email {email_id} marked complete")
    else:
        print("Mark-complete failed:", resp.text)

if __name__=="__main__":
    poll_sent_emails()
