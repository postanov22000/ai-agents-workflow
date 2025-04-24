import base64
import json
import os
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError

SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

def get_credentials():
    """Get valid credentials with automatic refresh handling"""
    creds = None
    if os.path.exists('token.json'):
        try:
            creds = Credentials.from_authorized_user_file('token.json', SCOPES)
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
                with open('token.json', 'w') as token:
                    token.write(creds.to_json())
        except (json.JSONDecodeError, ValueError) as e:
            print(f"Error loading credentials: {str(e)}")
            return None
    return creds

def get_unread_emails():
    creds = get_credentials()
    if not creds:
        print("No valid credentials available")
        return []
    
    try:
        service = build('gmail', 'v1', credentials=creds)
        results = service.users().messages().list(
            userId='me',
            labelIds=['INBOX', 'UNREAD'],
            maxResults=10
        ).execute()
        return results.get('messages', [])
    except Exception as e:
        print(f"Error fetching emails: {str(e)}")
        return []

def decode_email(msg):
    try:
        if 'parts' in msg['payload']:
            data = msg['payload']['parts'][0]['body']['data']
        else:
            data = msg['payload']['body']['data']
        return base64.urlsafe_b64decode(data).decode('utf-8')
    except Exception as e:
        print(f"Error decoding email: {str(e)}")
        return ""
