from email_processor import get_unread_emails, decode_email
from ai_response import generate_response
from auth import authenticate
from googleapiclient.discovery import build
import time
import os

def send_email(creds, to_email, subject, body):
    service = build('gmail', 'v1', credentials=creds)

    message = {
        'raw': base64.urlsafe_b64encode(
            f"To: {to_email}\r\nSubject: {subject}\r\n\r\n{body}".encode("utf-8")
        ).decode("utf-8")
    }

    service.users().messages().send(userId='me', body=message).execute()

def respond_to_emails():
    creds = authenticate()
    messages = get_unread_emails()
    service = build('gmail', 'v1', credentials=creds)  # build once, not inside loop

    for msg in messages:
        email_text = decode_email(msg)
        response = generate_response(email_text)

        # Fetch metadata to get the "From" address
        full_msg = service.users().messages().get(
            userId='me',
            id=msg['id'],
            format='metadata',
            metadataHeaders=['From']
        ).execute()

        from_email = None
        for header in full_msg['payload']['headers']:
            if header['name'] == 'From':
                from_email = header['value']
                break

        if from_email:
            send_email(creds, from_email, "Re: Your Email", response)

if __name__ == "__main__":
    if os.getenv("GITHUB_ACTIONS") == "true":
        respond_to_emails()
    else:
        while True:
            respond_to_emails()
            time.sleep(300)
