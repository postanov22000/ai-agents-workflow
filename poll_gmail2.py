import os
import base64
import logging
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
from supabase import create_client, Client
from typing import Optional
import re
import requests
from urllib.parse import unquote
from email.utils import parseaddr
from datetime import datetime, timezone
# Add at the top of poll_gmail.py
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from app import send_email_gmail



# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("gmail_poller")

import os
from supabase import create_client, Client

# Load Supabase environment vars
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY")
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")

# Initialize clients
supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
SUPABASE_SERVICE: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

# Supabase setup
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

def is_forwarding_confirmation_email(subject, body):
    """Check if this is a Gmail forwarding confirmation email"""
    forwarding_keywords = [
        'confirm your forward',
        'forwarding confirmation',
        'verify forwarding',
        'confirm forwarding',
        'forward emails from'
    ]
    
    subject_lower = subject.lower()
    body_lower = body.lower()
    
    for keyword in forwarding_keywords:
        if keyword in subject_lower or keyword in body_lower:
            return True
    return False

def extract_gmail_verification_link(text):
    """Extract Gmail forwarding verification link from email body"""
    # Gmail verification links typically look like:
    # https://mail-settings.google.com/mail/...
    patterns = [
        r'https://mail-settings\.google\.com/mail/[^\s<>"\'()]+',
        r'https://www\.google\.com/settings/forwarding/[^\s<>"\'()]+',
        r'https://accounts\.google\.com/VerifyForwarding/[^\s<>"\'()]+'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(0)
    return None

def extract_forwarding_email_from_confirmation(text):
    """Extract the email address that's trying to forward to us"""
    # Look for patterns like "forward emails from user@domain.com"
    patterns = [
        r'forward\s+emails\s+from\s+([^\s<>@]+@[^\s<>@]+\.[^\s<>@]+)',
        r'forwarding\s+emails\s+from\s+([^\s<>@]+@[^\s<>@]+\.[^\s<>@]+)',
        r'from\s+([^\s<>@]+@[^\s<>@]+\.[^\s<>@]+)\s+to\s+forward',
        r'([^\s<>@]+@[^\s<>@]+\.[^\s<>@]+)\s+is\s+requesting'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1).lower()
    return None

#-----------------------------------------------------------------------------------------------------------
def load_credentials(user_email: str) -> Optional[Credentials]:
    """Loads and optionally refreshes Gmail credentials from Supabase."""
    try:
        result = supabase.table("gmail_tokens2").select("credentials").eq("user_email", user_email).execute().data
        if not result:
            logger.warning(f"No credentials found for {user_email}")
            return None

        creds_data = result[0]["credentials"]

        creds = Credentials(
            token=creds_data["token"],
            refresh_token=creds_data["refresh_token"],
            token_uri=creds_data["token_uri"],
            client_id=creds_data["client_id"],
            client_secret=creds_data["client_secret"],
            scopes=creds_data.get("scopes", [
                "https://www.googleapis.com/auth/gmail.readonly",
                "https://www.googleapis.com/auth/gmail.send"
            ])
        )

        # Refresh token if expired
        if creds.expired or not creds.valid:
            try:
                creds.refresh(Request())
                # Save new token
                supabase.table("gmail_tokens2").upsert({
                    "user_email": user_email,
                    "credentials": {
                        "token": creds.token,
                        "refresh_token": creds.refresh_token,
                        "token_uri": creds.token_uri,
                        "client_id": creds.client_id,
                        "client_secret": creds.client_secret,
                        "scopes": creds.scopes
                    }
                }).execute()
            except RefreshError:
                logger.error(f"Token refresh failed for {user_email}")
                supabase.table("gmail_tokens2").update({"broken": True}).eq("user_email", user_email).execute()
                return None

        return creds

    except Exception as e:
        logger.exception(f"Unexpected error loading credentials for {user_email}: {e}")
        return None


def extract_plaintext(payload: dict) -> str:
    """Extracts plaintext from email payload."""
    try:
        if payload.get("mimeType") == "text/plain" and "data" in payload["body"]:
            return base64.urlsafe_b64decode(payload["body"]["data"]).decode("utf-8", errors="ignore")

        if "parts" in payload:
            for part in payload["parts"]:
                if part.get("mimeType") == "text/plain" and "data" in part.get("body", {}):
                    return base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8", errors="ignore")
    except Exception as e:
        logger.warning(f"Failed to extract plaintext: {e}")
    return ""


def extract_header(headers: list, key: str, default: str = "") -> str:
    for h in headers:
        if h.get("name", "").lower() == key.lower():
            return h.get("value", default)
    return default


def poll_gmail_for_user(user_email: str):
    logger.info(f"Polling Gmail for user: {user_email}")
    creds = load_credentials(user_email)
    if not creds:
        logger.warning(f"Skipping user due to missing or invalid credentials: {user_email}")
        return

    try:
        service = build("gmail", "v1", credentials=creds, cache_discovery=False)
        results = service.users().messages().list(userId="me", labelIds=["INBOX"], q="is:unread").execute()
        messages = results.get("messages", [])
    except Exception as e:
        logger.error(f"Failed to fetch messages for {user_email}: {e}")
        return

    for msg in messages:
        try:
            full = service.users().messages().get(userId="me", id=msg["id"], format="full").execute()
            payload = full.get("payload", {})
            headers = payload.get("headers", [])

            subject = extract_header(headers, "Subject", "(No Subject)")
            sender = extract_header(headers, "From")
            body = extract_plaintext(payload)


            if is_forwarding_confirmation_email(subject, body):
                logger.info(f"📧 Found forwarding confirmation email: {subject}")
                if handle_forwarding_confirmation(body, subject, sender):
                    # Mark as read and processed
                    service.users().messages().modify(
                        userId="me", 
                        id=msg["id"], 
                        body={'removeLabelIds': ['UNREAD']}
                    ).execute()
                    logger.info("✅ Forwarding confirmation processed successfully")
                continue

                
            # Skip if already exists
            exists = supabase.table("emails").select("id").eq("gmail_id", msg["id"]).execute().data
            if exists:
                logger.info(f"Skipping duplicate email: {msg['id']}")
                continue

            # Get user_id from profiles table
            user_entry = supabase.table("profiles").select("id").eq("email", user_email).execute().data
            if not user_entry:
                logger.warning(f"No user_id found for {user_email}, skipping email.")
                continue

            user_id = user_entry[0]["id"]

            supabase.table("emails").insert({
                "user_id": user_id,
                "sender_email": sender,
                "recipient_email": user_email,
                "subject": subject,
                "original_content": body,
                "status": "processing",
                "gmail_id": msg["id"]
            }).execute()

            logger.info(f"Inserted email for {user_email}: {subject}")

        except Exception as e:
            logger.exception(f"Error processing message {msg.get('id', '?')} for {user_email}: {e}")


if __name__ == "__main__":
    try:
        users = supabase.table("gmail_tokens2").select("user_email").eq("broken", False).execute().data
        for user in users:
            poll_gmail_for_user(user["user_email"])
    except Exception as e:
        logger.exception(f"Failed during user polling loop: {e}")

import re
import email
from email.header import decode_header

def parse_forwarded_email(raw_email):
    """Parse forwarded email to extract original recipient and content"""
    try:
        # Decode email headers
        headers = raw_email.get('payload', {}).get('headers', [])
        
        # Extract subject to check if it's forwarded
        subject = extract_header(headers, "Subject", "").lower()
        is_forwarded = "fwd:" in subject or "fw:" in subject
        
        original_recipient = None
        original_sender = None
        original_content = ""
        
        if is_forwarded:
            body = extract_plaintext(raw_email.get('payload', {}))
            
            # Try to extract original recipient from forwarding headers
            # Look for patterns like "Original Recipient:", "To:", in the forwarded message
            original_recipient_patterns = [
                r'Original-Recipient:\s*rfc822;([^\s@]+@[^\s@]+\.[^\s@]+)',
                r'To:\s*([^\s@]+@[^\s@]+\.[^\s@]+)',
                r'Originally sent to:\s*([^\s@]+@[^\s@]+\.[^\s@]+)'
            ]
            
            for pattern in original_recipient_patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    original_recipient = match.group(1).strip()
                    break
            
            # If no pattern matched, try to extract from common forwarding formats
            if not original_recipient:
                # Look for email patterns in the forwarded header section
                email_pattern = r'[\w\.-]+@[\w\.-]+\.\w+'
                emails_in_body = re.findall(email_pattern, body)
                
                # The original recipient is likely one of the first emails found
                for found_email in emails_in_body:
                    if found_email != raw_email.get('sender_email'):
                        original_recipient = found_email
                        break
            
            # Extract original content by removing forwarding headers
            lines = body.split('\n')
            in_original_content = False
            cleaned_lines = []
            
            for line in lines:
                if any(x in line.lower() for x in ['forwarded message', 'original message', 'begin forwarded message']):
                    in_original_content = True
                    continue
                if in_original_content and line.strip():
                    cleaned_lines.append(line)
            
            original_content = '\n'.join(cleaned_lines) if cleaned_lines else body
        
        return {
            'is_forwarded': is_forwarded,
            'original_recipient': original_recipient,
            'original_content': original_content if is_forwarded else body,
            'original_sender': original_sender
        }
        
    except Exception as e:
        logger.error(f"Error parsing forwarded email: {str(e)}")
        return {
            'is_forwarded': False,
            'original_recipient': None,
            'original_content': extract_plaintext(raw_email.get('payload', {})),
            'original_sender': None
        }

def poll_gmail_for_user(user_email: str):
    logger.info(f"Polling Gmail for user: {user_email}")
    creds = load_credentials(user_email)
    if not creds:
        logger.warning(f"Skipping user due to missing or invalid credentials: {user_email}")
        return

    try:
        service = build("gmail", "v1", credentials=creds, cache_discovery=False)
        results = service.users().messages().list(userId="me", labelIds=["INBOX"], q="is:unread").execute()
        messages = results.get("messages", [])
    except Exception as e:
        logger.error(f"Failed to fetch messages for {user_email}: {e}")
        return

    for msg in messages:
        try:
            full = service.users().messages().get(userId="me", id=msg["id"], format="full").execute()
            payload = full.get("payload", {})
            headers = payload.get("headers", [])

            subject = extract_header(headers, "Subject", "(No Subject)")
            sender = extract_header(headers, "From")
            body = extract_plaintext(payload)

            # Skip if already exists
            exists = supabase.table("emails").select("id").eq("gmail_id", msg["id"]).execute().data
            if exists:
                logger.info(f"Skipping duplicate email: {msg['id']}")
                continue

            # Parse forwarded email to extract original recipient
            parsed_email = parse_forwarded_email({
                'payload': payload,
                'sender_email': sender
            })

            # Find the correct user_id based on original recipient
            target_user_id = None
            if parsed_email['is_forwarded'] and parsed_email['original_recipient']:
                # Look up user by original recipient email
                user_entry = supabase.table("profiles").select("id").eq("email", parsed_email['original_recipient']).execute().data
                if user_entry:
                    target_user_id = user_entry[0]["id"]
                    logger.info(f"Found target user {target_user_id} for original recipient {parsed_email['original_recipient']}")
                else:
                    logger.warning(f"No user found for original recipient: {parsed_email['original_recipient']}")

            # If no target user found, use polling account's user_id as fallback
            if not target_user_id:
                user_entry = supabase.table("profiles").select("id").eq("email", user_email).execute().data
                if not user_entry:
                    logger.warning(f"No user_id found for {user_email}, skipping email.")
                    continue
                target_user_id = user_entry[0]["id"]

            # Insert email with proper user association
            email_data = {
                "user_id": target_user_id,
                "sender_email": sender,
                "recipient_email": user_email,  # The polling account that received it
                "original_recipient_email": parsed_email['original_recipient'],
                "polling_account_email": user_email,
                "is_forwarded": parsed_email['is_forwarded'],
                "subject": subject,
                "original_content": parsed_email['original_content'],
                "status": "processing",
                "gmail_id": msg["id"]
            }

            supabase.table("emails").insert(email_data).execute()
            logger.info(f"Inserted email for user {target_user_id} via polling account {user_email}: {subject}")

        except Exception as e:
            logger.exception(f"Error processing message {msg.get('id', '?')} for {user_email}: {e}")




import re
import requests
from urllib.parse import unquote
from email.utils import parseaddr



def click_verification_link(verification_url):
    """Simulate clicking the Gmail verification link"""
    try:
        # Follow redirects and handle Google's verification process
        session = requests.Session()
        
        # Set realistic headers to avoid being blocked
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        response = session.get(verification_url, headers=headers, timeout=30, allow_redirects=True)
        
        if response.status_code == 200:
            logger.info(f"✅ Successfully clicked verification link: {response.url}")
            return True
        else:
            logger.warning(f"⚠️ Verification link returned status {response.status_code}")
            return False
            
    except Exception as e:
        logger.error(f"❌ Failed to click verification link: {str(e)}")
        return False

def is_user_in_database(user_email):
    """Check if the email belongs to a registered user"""
    try:
        result = supabase.table("profiles") \
            .select("id, email, full_name") \
            .eq("email", user_email) \
            .execute()
        
        return len(result.data) > 0
    except Exception as e:
        logger.error(f"Error checking user in database: {str(e)}")
        return False

def handle_forwarding_confirmation(email_body, email_subject, sender_email):
    """Process Gmail forwarding confirmation emails"""
    try:
        # Extract the verification link
        verification_link = extract_gmail_verification_link(email_body)
        if not verification_link:
            logger.info("No verification link found in email")
            return False
        
        # Extract the email address that's trying to forward to us
        forwarding_email = extract_forwarding_email_from_confirmation(email_body)
        if not forwarding_email:
            logger.info("Could not extract forwarding email address from confirmation")
            return False
        
        logger.info(f"Found forwarding request from: {forwarding_email}")
        logger.info(f"Verification link: {verification_link}")
        
        # Check if this is a registered user
        if is_user_in_database(forwarding_email):
            logger.info(f"✅ {forwarding_email} is a registered user - auto-verifying...")
            
            # Click the verification link
            if click_verification_link(verification_link):
                # Mark user as forwarding verified in database
                mark_user_as_verified(forwarding_email)
                
                # Send confirmation to user
                send_forwarding_setup_confirmation(forwarding_email)
                return True
            else:
                logger.error(f"Failed to auto-verify {forwarding_email}")
                return False
        else:
            logger.info(f"❌ {forwarding_email} is not a registered user - ignoring forwarding request")
            return False
            
    except Exception as e:
        logger.error(f"Error handling forwarding confirmation: {str(e)}")
        return False

def mark_user_as_verified(user_email):
    """Mark user as having verified email forwarding"""
    try:
        result = supabase.table("profiles") \
            .update({
                "forwarding_verified": True,
                "forwarding_verified_at": datetime.now(timezone.utc).isoformat()
            }) \
            .eq("email", user_email) \
            .execute()
        
        if result.data:
            logger.info(f"✅ Marked {user_email} as forwarding verified")
            return True
        return False
    except Exception as e:
        logger.error(f"Error marking user as verified: {str(e)}")
        return False

def send_forwarding_setup_confirmation(user_email):
    """Send email confirmation that forwarding is setup"""
    try:
        user_result = supabase.table("profiles") \
            .select("id, full_name") \
            .eq("email", user_email) \
            .single() \
            .execute()
        
        if not user_result.data:
            return
        
        user = user_result.data
        subject = "✅ Email Forwarding Successfully Setup!"
        
        html_content = f"""
        <html>
        <body>
            <h2>Email Forwarding Activated! 🎉</h2>
            <p>Hello {user['full_name'] or 'there'},</p>
            <p>Your email forwarding has been automatically verified and is now active!</p>
            <p><strong>What's next?</strong></p>
            <ul>
                <li>Any emails forwarded to your dedicated address will be automatically processed</li>
                <li>You'll see AI-generated responses in your dashboard</li>
                <li>No additional setup required - you're all set!</li>
            </ul>
            <p>Start forwarding client emails and watch the magic happen! ✨</p>
        </body>
        </html>
        """
        
        # Send via Gmail API
        success, message = send_email_gmail(
            user['id'],
            user_email,
            subject,
            html_content
        )
        
        if success:
            logger.info(f"Sent forwarding confirmation to {user_email}")
        else:
            logger.error(f"Failed to send forwarding confirmation: {message}")
            
    except Exception as e:
        logger.error(f"Error sending forwarding confirmation: {str(e)}")

