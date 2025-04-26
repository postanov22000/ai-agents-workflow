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
GMAIL_CREDENTIALS_FILE = 'credentials.json'  # Path to your Google credentials file
SCOPES = ['https://www.googleapis.com/auth/gmail.send']

# Poll Supabase for emails with status 'sent'
def poll_sent_emails():
    headers = {
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
    }
    while True:
        # Fetch emails with status 'sent'
        response = requests.get(f"{SUPABASE_URL}/rest/v1/emails?status=eq.sent", headers=headers)
        if response.status_code != 200:
            print(f"Error fetching emails: {response.text}")
            time.sleep(30)
            continue

        emails = response.json()

        for email in emails:
            # Call Gmail API to send email
            send_email_via_gmail(email)

            # Mark email as complete in Supabase
            mark_email_complete(email['id'])

        time.sleep(30)  # Poll every 30 seconds

# Function to authenticate and get Gmail API credentials
def authenticate_gmail():
    creds = None
    if os.path.exists('token.json'):  # Check if token exists to skip login
        creds = service_account.Credentials.from_service_account_file(
            'token.json', scopes=SCOPES)

    # If no valid credentials, let the user log in
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                GMAIL_CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)

        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    return creds

# Function to build Gmail service using the credentials
def build_gmail_service():
    creds = authenticate_gmail()
    service = build('gmail', 'v1', credentials=creds)
    return service

# Function to send email using Gmail API
def send_email_via_gmail(email):
    service = build_gmail_service()
    message = create_message(email['sender_email'], email['recipient_email'], email['subject'], email['ai_response'])
    send_message(service, 'me', message)

# Function to create an email message
def create_message(sender, to, subject, body):
    # Create the raw email message
    message = {
        'raw': base64.urlsafe_b64encode(f"From: {sender}\nTo: {to}\nSubject: {subject}\n\n{body}".encode('utf-8')).decode('utf-8')
    }
    return message

# Function to send the message using Gmail API
def send_message(service, sender, message):
    try:
        message = service.users().messages().send(userId=sender, body=message).execute()
        print(f"Message sent: {message['id']}")
    except Exception as error:
        print(f"An error occurred: {error}")

# Function to mark email as complete in Supabase
def mark_email_complete(email_id):
    data = {
        "status": "complete"
    }
    response = requests.patch(
        f"{SUPABASE_URL}/rest/v1/emails?id=eq.{email_id}",
        json=data,
        headers={
            "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
            "Content-Type": "application/json",
        }
    )
    if response.status_code == 200:
        print(f"Email {email_id} marked as complete.")
    else:
        print(f"Failed to mark email {email_id} as complete.")

if __name__ == "__main__":
    poll_sent_emails()
