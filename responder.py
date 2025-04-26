import requests, os, time, base64, json
from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

# configuration from environment
SUPABASE_URL               = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY  = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
GMAIL_CREDENTIALS_FILE     = 'credentials.json'   # OAuth “installed app” JSON
TOKEN_FILE                 = 'token.json'
SCOPES                     = ['https://www.googleapis.com/auth/gmail.send']

def authenticate_gmail():
    creds = None
    # reuse saved token if present
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    # if no valid credentials, run console flow
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(GMAIL_CREDENTIALS_FILE, SCOPES)
            creds = flow.run_console()        # ← prints URL; paste code back
        # save for next time
        with open(TOKEN_FILE, 'w') as f:
            f.write(creds.to_json())
    return creds

def build_gmail_service():
    creds = authenticate_gmail()
    return build('gmail', 'v1', credentials=creds)

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

def mark_email_complete(email_id):
    headers = {
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "apikey":       SUPABASE_SERVICE_ROLE_KEY,
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

def poll_sent_emails():
    headers = {
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "apikey":       SUPABASE_SERVICE_ROLE_KEY,
        "Content-Type": "application/json",
    }
    while True:
        resp = requests.get(f"{SUPABASE_URL}/rest/v1/emails?status=eq.sent", headers=headers)
        if resp.status_code != 200:
            print("Error fetching emails:", resp.text)
            time.sleep(30)
            continue
        emails = resp.json()
        print(f"⏱️ Found {len(emails)} emails with status=sent")
        for email in emails:
            send_email_via_gmail(email)
            mark_email_complete(email['id'])
        time.sleep(30)

if __name__=="__main__":
    poll_sent_emails()
