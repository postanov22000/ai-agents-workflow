from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

def send_email(creds, to, subject, body_text):
    service = build('gmail', 'v1', credentials=creds)
    from email.mime.text import MIMEText
    import base64

    message = MIMEText(body_text)
    message['to'] = to
    message['subject'] = subject
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()

    try:
        message = service.users().messages().send(userId="me", body={'raw': raw}).execute()
        print(f"✅ Sent email to {to}, ID: {message['id']}")
    except HttpError as error:
        print(f"❌ Failed to send email: {error}")
