import requests
import json
import os
import time

# Load environment variables
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
HUGGINGFACE_API_KEY = os.getenv("HUGGINGFACE_API_KEY")
GMAIL_API_KEY = os.getenv("GMAIL_API_KEY")

# Poll Supabase for emails with status 'sent'
def poll_sent_emails():
    headers = {
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
    }
    while True:
        # Fetch emails with status 'sent'
        response = requests.get(f"{SUPABASE_URL}/rest/v1/emails?status=eq.sent", headers=headers)
        emails = response.json()

        for email in emails:
            # Call Gmail API to send email
            send_email_via_gmail(email)

            # Mark email as complete in Supabase
            mark_email_complete(email['id'])

        time.sleep(30)  # Poll every 30 seconds

# Function to send email using Gmail API
def send_email_via_gmail(email):
    # Logic for sending the email using Gmail API
    pass

# Function to mark email as complete
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
