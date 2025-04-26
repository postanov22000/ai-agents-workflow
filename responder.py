import requests
import json
import os
import time
import base64
from google.oauth2 import service_account
from googleapiclient.discovery import build

# Load environment variables
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

# Gmail credentials (service account JSON if using service accounts)
GMAIL_USER = os.getenv("GMAIL_USER")  # your Gmail address

# Load credentials for Gmail API
creds = service_account.Credentials.from_service_account_file(
    'credentials.json',
    scopes=["https://www.googleapis.com/auth/gmail.send"]
)

gmail_service = build('gmail', 'v1', credentials=creds)

def create_email(sender, to, subject, message_text):
    message = {
        'raw': base64.urlsafe_b64encode(
            f"From: {sender}\r\nTo: {to}\r\nSubject: {subject}\r\n\r\n{message_text}".encode("utf-8")
        ).decode('utf-8')
    }
    return message

# Poll Supabase for emails with status 'sent'
def poll_sent_emails():
    headers = {
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Content-Type": "application/json",
    }
    while True:
        # Fetch emails with status 'sent'
        response = requests.get(
            f"{SUPABASE_URL}/rest/v1/emails?status=eq.sent&select=*",
            headers=headers
        )
        if response.status_code != 200:
            print(f"Error fetching emails: {response.text}")
            time.sleep(30)
            continue

        emails = response.json()

        for email in emails:
            # Call Gmail API to send email
            send_email_via_gmail(email)

            # Mark email as complete
            mark_email_complete(email['id'])

        time.sleep(30)  # Poll every 30 seconds

# Function to send email using Gmail API
def send_email_via_gmail(email):
    try:
        message = create_email(
            GMAIL_USER,
            email['recipient_email'],
            email['subject'] or "No subject",
            email['ai_response'] or "No content"
        )
        sent_message = gmail_service.users().messages().send(userId="me", body=message).execute()
        print(f"Sent email to {email['recipient_email']}, ID: {sent_message['id']}")
    except Exception as e:
        print(f"Error sending email: {e}")

# Function to mark email as complete
def mark_email_complete(email_id):
    data = {
        "status": "complete"
    }
    response = requests.patch(
        f"{SUPABASE_URL}/rest/v1/emails?id=eq.{email_id}",
        headers={
            "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
            "apikey": SUPABASE_SERVICE_ROLE_KEY,
            "Content-Type": "application/json",
        },
        json=data
    )
    if response.status_code == 204:
        print(f"Email {email_id} marked as complete.")
    else:
        print(f"Failed to mark email {email_id} as complete: {response.text}")

if __name__ == "__main__":
    poll_sent_emails()
