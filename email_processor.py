import base64
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials  # <-- Add this import

# Your existing SCOPES definition
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

def get_unread_emails():
    creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    service = build('gmail', 'v1', credentials=creds)
    results = service.users().messages().list(userId='me', labelIds=['INBOX', 'UNREAD']).execute()
    return results.get('messages', [])

def decode_email(msg):
    data = msg['payload']['parts'][0]['body']['data']
    return base64.urlsafe_b64decode(data).decode('utf-8')
