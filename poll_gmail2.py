import os
import base64
import logging
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
from supabase import create_client, Client
from typing import Optional

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("gmail_poller")

# Supabase setup
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)


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
