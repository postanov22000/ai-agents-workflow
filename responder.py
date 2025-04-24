from email_processor import get_unread_emails, decode_email
from ai_response import generate_response
from auth import authenticate
import time
import os

def respond_to_emails():
    creds = authenticate()
    messages = get_unread_emails()
    for msg in messages:
        email_text = decode_email(msg)
        response = generate_response(email_text)
        # ... rest of your email sending logic

if __name__ == "__main__":
    if os.getenv("GITHUB_ACTIONS") == "true":
        respond_to_emails()  # Run once
    else:
        while True:  # Local testing
            respond_to_emails()
            time.sleep(300)
