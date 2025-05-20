import os
import logging
import requests
from datetime import datetime, timezone
from email.mime.text import MIMEText
import base64
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
from supabase import create_client, Client

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Supabase setup
def get_supabase() -> Client:
    try:
        return create_client(
            os.environ["SUPABASE_URL"],
            os.environ["SUPABASE_SERVICE_ROLE_KEY"]
        )
    except KeyError as e:
        logger.error(f"Missing environment variable: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Supabase initialization failed: {str(e)}")
        raise

supabase = get_supabase()

def load_credentials(sender_email: str) -> Credentials:
    """Load and refresh Gmail credentials from Supabase"""
    try:
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
            logger.info(f"Refreshing expired credentials for {sender_email}")
            try:
                creds.refresh(Request())
            except RefreshError as e:
                if 'invalid_grant' in str(e).lower():
                    # Delete invalid credentials
                    supabase.table('gmail_tokens') \
                           .delete() \
                           .eq('user_email', sender_email) \
                           .execute()
                    logger.error(f"Deleted invalid credentials for {sender_email}")
                    
                    # Mark all user's emails as needing reauthentication
                    supabase.table('emails') \
                           .update({'status': 'needs_reauthentication'}) \
                           .eq('sender_email', sender_email) \
                           .execute()
                    
                    raise ValueError("Session expired. Please re-authenticate your Gmail.")
                raise

            # Update Supabase with new credentials
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

    except Exception as e:
        logger.error(f"Credentials error for {sender_email}: {str(e)}")
        raise

def create_message(to: str, subject: str, body: str) -> dict:
    """Create a MIME message for Gmail API"""
    try:
        message = MIMEText(body)
        message["to"] = to
        message["subject"] = subject
        return {
            "raw": base64.urlsafe_b64encode(message.as_bytes()).decode()
        }
    except Exception as e:
        logger.error(f"Message creation failed: {str(e)}")
        raise

def process_single_email(email: dict) -> None:
    """Process a single email through AI and update status"""
    email_id = email["id"]
    try:
        # Update status to processing
        supabase.table("emails") \
            .update({"status": "processing"}) \
            .eq("id", email_id) \
            .execute()

        # Generate AI response
        prompt = (
            "[INST]You are a professional real estate agent. "
            "Respond to this email in a friendly and professional manner:\n\n"
            f"{email['original_content']}[/INST]"
        )
        
        response = requests.post(
            "https://api-inference.huggingface.co/models/mistralai/Mixtral-8x7B-Instruct-v0.1",
            headers={"Authorization": f"Bearer {os.environ['HF_API_KEY']}"},
            json={
                "inputs": prompt,
                "parameters": {
                    "max_new_tokens": 500,
                    "temperature": 0.7
                },
                "options": {"use_cache": False}
            },
            timeout=30
        )

        if response.status_code != 200:
            raise ValueError(f"API Error {response.status_code}: {response.text[:200]}")

        try:
            reply = response.json()[0]["generated_text"].strip()
        except (KeyError, IndexError):
            raise ValueError("Unexpected API response format")

        # Update with processed content
        supabase.table("emails") \
            .update({
                "processed_content": reply,
                "status": "ready_to_send",
                "processed_at": datetime.now(timezone.utc).isoformat()
            }) \
            .eq("id", email_id) \
            .execute()

    except Exception as e:
        logger.error(f"Processing failed for email {email_id}: {str(e)}")
        supabase.table("emails") \
            .update({
                "status": "error",
                "error_message": str(e)[:500]
            }) \
            .eq("id", email_id) \
            .execute()

def send_single_email(email: dict) -> None:
    """Send a single email and update status"""
    email_id = email["id"]
    try:
        sender = email["sender_email"]
        recipient = email["recipient_email"]
        subject = email.get("subject") or "Re: Your inquiry"
        body = email["processed_content"]

        # Load credentials and send email
        creds = load_credentials(sender)
        service = build("gmail", "v1", credentials=creds, cache_discovery=False)
        msg = create_message(recipient, subject, body)
        service.users().messages().send(userId="me", body=msg).execute()

        # Update status to sent
        supabase.table("emails") \
            .update({
                "status": "sent",
                "sent_at": datetime.now(timezone.utc).isoformat()
            }) \
            .eq("id", email_id) \
            .execute()

    except Exception as e:
        logger.error(f"Sending failed for email {email_id}: {str(e)}")
        
        # Special handling for credential issues
        if 'invalid_grant' in str(e).lower():
            supabase.table('emails') \
                   .update({'status': 'needs_reauthentication'}) \
                   .eq('id', email_id) \
                   .execute()
        else:
            supabase.table("emails") \
                .update({
                    "status": "failed",
                    "error_message": str(e)[:500]
                }) \
                .eq("id", email_id) \
                .execute()

def run_worker() -> str:
    """Main worker function to process emails"""
    try:
        logger.info("Starting email processing")
        
        # Process preprocessing emails (skip needs_reauthentication)
        preprocessing = supabase.table("emails") \
                              .select("*") \
                              .eq("status", "preprocessing") \
                              .neq("sender_email", 
                                   supabase.table('emails')
                                          .select('sender_email')
                                          .eq('status', 'needs_reauthentication')
                                          .execute()
                                          .data
                                  ) \
                              .execute().data
        
        for email in preprocessing:
            process_single_email(email)

        # Process ready-to-send emails (skip needs_reauthentication)
        ready = supabase.table("emails") \
                       .select("*") \
                       .eq("status", "ready_to_send") \
                       .neq("sender_email",
                            supabase.table('emails')
                                   .select('sender_email')
                                   .eq('status', 'needs_reauthentication')
                                   .execute()
                                   .data
                           ) \
                       .execute().data
        
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
