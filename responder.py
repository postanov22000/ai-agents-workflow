from email_processor import get_unread_emails, decode_email
from ai_response import generate_response
from auth import get_credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

def send_email(creds, to, subject, body):
    try:
        service = build('gmail', 'v1', credentials=creds)
        message = service.users().messages().send(
            userId='me',
            body={
                'raw': create_message(to, subject, body)
            }
        ).execute()
        print(f"Message sent to {to} with subject: {subject}")
    except HttpError as error:
        print(f"An error occurred: {error}")

def create_message(to, subject, body):
    """Create a message for sending an email."""
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    import base64

    message = MIMEMultipart()
    message['to'] = to
    message['subject'] = subject
    msg = MIMEText(body)
    message.attach(msg)

    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

    return raw_message

def respond_to_emails():
    creds = get_credentials()
    messages = get_unread_emails()
    for msg in messages:
        email_text = decode_email(msg)
        response = generate_response(email_text)

        # Fetch metadata to get the "From" address
        service = build('gmail', 'v1', credentials=creds)
        full_msg = service.users().messages().get(userId='me', id=msg['id'], format='metadata', metadataHeaders=['From']).execute()
        from_email = None
        for header in full_msg['payload']['headers']:
            if header['name'] == 'From':
                from_email = header['value']
                break

        if from_email:
            send_email(creds, from_email, "Re: Your Email", response)

if __name__ == "__main__":
    respond_to_emails()
