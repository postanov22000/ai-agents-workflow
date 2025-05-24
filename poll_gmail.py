import os
import base64
import logging
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
from supabase import create_client, Client
from postgrest.exceptions import APIError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("gmail_poller")

# Supabase setup
SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_SERVICE_ROLE_KEY = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

def safe_get_users():
    """Return all users or filter out broken ones if column exists."""
    try:
        return supabase.table("gmail_tokens").select("user_email").eq("broken", False).execute().data
    except APIError as e:
        if "column gmail_tokens.broken does not exist" in str(e):
            logger.warning("Column 'broken' does not exist. Fetching all users instead.")
            return supabase.table("gmail_tokens").select("user_email").execute().data
        else:
            logger.error(f"Supabase user fetch failed: {e}")
            return []

def load_credentials(user_email: str):
    """Loads and optionally refreshes Gmail credentials."""
    result = supabase.table("gmail_tokens").select("credentials").eq("user_email", user_email).execute().data
    if not result:
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

    # Refresh if needed
    if creds.expired or not creds.valid:
        try:
            creds.refresh(Request())
            # Save refreshed token
            supabase.table("gmail_tokens").upsert({
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
            logger.error(f"Token refresh failed for {user_email}. Marking as broken.")
            try:
                supabase.table("gmail_tokens").update({"broken": True}).eq("user_email", user_email).execute()
            except APIError as e:
                logger.warning(f"Could not mark token as broken: {e}")
            return None

    return creds

def extract_plaintext(payload):
    if payload["mimeType"] == "text/plain" and "data" in payload["body"]:
        return base64.urlsafe_b64decode(payload["body"]["data"]).decode("utf-8", errors="ignore")
    elif "parts" in payload:
        for part in payload["parts"]:
            if part["mimeType"] == "text/plain" and "data" in part["body"]:
                return base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8", errors="ignore")
    return ""

def extract_sender(headers):
    for h in headers:
        if h["name"].lower() == "from":
            return h["value"]
    return ""

def extract_subject(headers):
    for h in headers:
        if h["name"].lower() == "subject":
            return h["value"]
    return "(No Subject)"

def poll_gmail_for_user(user_email):
    creds = load_credentials(user_email)
    if not creds:
        logger.warning(f"Skipping user due to missing or invalid creds: {user_email}")
        return

    service = build("gmail", "v1", credentials=creds, cache_discovery=False)

    try:
        results = service.users().messages().list(userId="me", labelIds=["INBOX"], q="is:unread").execute()
    except Exception as e:
        logger.error(f"Failed to fetch messages for {user_email}: {str(e)}")
        return

    messages = results.get("messages", [])

    for msg in messages:
        try:
            full = service.users().messages().get(userId="me", id=msg["id"], format="full").execute()
            payload = full["payload"]
            headers = payload.get("headers", [])

            subject = extract_subject(headers)
            sender = extract_sender(headers)
            body = extract_plaintext(payload)

            # Avoid duplicates
            exists = supabase.table("emails").select("id").eq("gmail_id", msg["id"]).execute().data
            if exists:
                continue

            # Get user_id for foreign key
            user_entry = supabase.table("profiles").select("id").eq("email", user_email).execute().data
            user_id = user_entry[0]["id"] if user_entry else None

            if not user_id:
                logger.warning(f"No user_id found for {user_email}, skipping email.")
                continue

            # Insert email
            supabase.table("emails").insert({
                "user_id": user_id,
                "sender_email": sender,
                "recipient_email": user_email,
                "subject": subject,
                "original_content": body,
                "status": "preprocessing",
                "gmail_id": msg["id"]
            }).execute()

            logger.info(f"Inserted email for {user_email}: {subject}")
        except Exception as e:
            logger.error(f"Failed to process message {msg['id']} for {user_email}: {str(e)}")

if __name__ == "__main__":
    users = safe_get_users()
    for user in users:
        poll_gmail_for_user(user["user_email"])
