from email_processor import get_unread_emails, decode_email
from ai_response import generate_response
from auth import authenticate
import time

def main():
    creds = authenticate()
    while True:
        messages = get_unread_emails()
        for msg in messages:
            email_text = decode_email(msg)
            response = generate_response(email_text)
            
            # Create reply
            raw_response = f"From: your_email@gmail.com\nTo: {msg['from']}\nSubject: Re: {msg['subject']}\n\n{response}"
            
            # Send email
            service = build('gmail', 'v1', credentials=creds)
            message = {'raw': base64.urlsafe_b64encode(raw_response.encode()).decode()}
            service.users().messages().send(userId='me', body=message).execute()
            
        time.sleep(300)  # Check every 5 minutes

if __name__ == "__main__":
    main()
