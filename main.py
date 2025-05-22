import os
import logging
import requests
from datetime import datetime, timezone
from email.mime.text import MIMEText
import base64
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from supabase import create_client, Client

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Parse multiple Hugging Face keys from HF_API_KEY
HF_API_KEYS = [k.strip() for k in os.environ.get("HF_API_KEY", "").split(",")]
current_key_index = 0

# Supabase setup
def get_supabase() -> Client:
    return create_client(
        os.environ["SUPABASE_URL"],
        os.environ["SUPABASE_SERVICE_ROLE_KEY"]
    )

supabase = get_supabase()

def load_credentials(sender_email: str) -> Credentials:
    response = supabase.table('gmail_tokens') \
        .select('credentials') \
        .eq('user_email', sender_email) \
        .execute()

    if not response.data:
        raise ValueError(f"No Gmail credentials found for {sender_email}")

    creds_data = response.data[0]['credentials']
    creds = Credentials(
        token=creds_data.get('token'),
        refresh_token=creds_data.get('refresh_token'),
        token_uri=creds_data.get('token_uri', 'https://oauth2.googleapis.com/token'),
        client_id=creds_data.get('client_id'),
        client_secret=creds_data.get('client_secret'),
        scopes=creds_data.get('scopes', [
            "https://www.googleapis.com/auth/gmail.send",
            "https://www.googleapis.com/auth/userinfo.email",
            "openid"
        ])
    )

    if creds.expired:
        creds.refresh(Request())
        supabase.table('gmail_tokens').upsert({
            'user_email': sender_email,
            'credentials': {
                'token': creds.token,
                'refresh_token': creds.refresh_token,
                'token_uri': creds.token_uri,
                'client_id': creds.client_id,
                'client_secret': creds.client_secret,
                'scopes': creds.scopes
            }
        }).execute()

    return creds

def create_message(to: str, subject: str, body: str) -> dict:
    message = MIMEText(body)
    message["to"] = to
    message["subject"] = subject
    return {
        "raw": base64.urlsafe_b64encode(message.as_bytes()).decode()
    }

def process_single_email(email: dict) -> None:
    email_id = email["id"]

    try:
        supabase.table("emails").update({"status": "processing"}).eq("id", email_id).execute()

        # 🔧 Static mock boilerplate (could later pull from Supabase)
        template_text = "The property is located in a prime area and offers solid investment potential."

        # 🔧 Past style examples (from prior sent emails)
        past_emails = [
            "This asset is positioned in a high-demand submarket with minimal vacancy.",
            "Strategically located near top-performing retail anchors, providing steady foot traffic."
        ]

        # 🔧 Example deal data (this could come from parsing or Supabase)
        deal_data = {
            "market": "SoHo",
            "cap_rate": "5.2%",
            "tenant": "Chase Bank"
        }

        # 🔁 POST to Edge Function
        personalize_url = os.environ.get("PERSONALIZE_FUNCTION_URL")  # add this to your .env

        if not personalize_url:
            raise ValueError("Missing PERSONALIZE_FUNCTION_URL environment variable")

        response = requests.post(
            personalize_url,
            json={
                "template_text": template_text,
                "past_emails": past_emails,
                "deal_data": deal_data
            },
            timeout=60
        )

        if response.status_code != 200:
            raise ValueError(f"Personalization failed: {response.status_code} - {response.text[:300]}")

        reply = response.json().get("result", "").strip()
        if not reply:
            raise ValueError("Personalization returned empty result")

        supabase.table("emails").update({
            "processed_content": reply,
            "status": "ready_to_send",
            "processed_at": datetime.now(timezone.utc).isoformat()
        }).eq("id", email_id).execute()

    except Exception as e:
        logger.error(f"Processing failed for email {email_id}: {str(e)}")
        supabase.table("emails").update({
            "status": "error",
            "error_message": str(e)[:500]
        }).eq("id", email_id).execute()

def send_single_email(email: dict) -> None:
    email_id = email["id"]
    try:
        sender = email["sender_email"]
        recipient = email["recipient_email"]
        subject = email.get("subject") or "Re: Your inquiry"
        body = email["processed_content"]

        creds = load_credentials(sender)
        service = build("gmail", "v1", credentials=creds, cache_discovery=False)
        msg = create_message(recipient, subject, body)
        service.users().messages().send(userId="me", body=msg).execute()

        supabase.table("emails").update({
            "status": "sent",
            "sent_at": datetime.now(timezone.utc).isoformat()
        }).eq("id", email_id).execute()

    except Exception as e:
        logger.error(f"Sending failed for email {email_id}: {str(e)}")
        supabase.table("emails").update({
            "status": "failed",
            "error_message": str(e)[:500]
        }).eq("id", email_id).execute()

def run_worker() -> str:
    try:
        logger.info("Starting email processing")

        preprocessing = supabase.table("emails").select("*").eq("status", "preprocessing").execute().data
        for email in preprocessing:
            process_single_email(email)

        ready = supabase.table("emails").select("*").eq("status", "ready_to_send").execute().data
        for email in ready:
            send_single_email(email)

        result = f"Processed {len(preprocessing)} emails, sent {len(ready)} emails"
        logger.info(result)
        return result

    except Exception as e:
        logger.error(f"Worker failed: {str(e)}")
        return f"Error: {str(e)}"

if __name__ == "__main__":
    run_worker()
