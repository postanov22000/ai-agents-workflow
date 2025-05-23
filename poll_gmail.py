import os
import base64
import logging
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from supabase import create_client

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("gmail_poller")

# Supabase connection
SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_SERVICE_ROLE_KEY = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

def load_credentials(user_email: str):
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
    if creds.expired:
        creds.refresh(Request())
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
        logger.warning(f"No creds for {user_email}")
        return

    service = build("gmail", "v1", credentials=creds, cache_discovery=False)
    results = service.users().messages().list(userId="me", labelIds=["INBOX"], q="is:unread").execute()
    messages = results.get("messages", [])

    for msg in messages:
        full = service.users().messages().get(userId="me", id=msg["id"], format="full").execute()
        payload = full["payload"]
        headers = payload.get("headers", [])

        subject = extract_subject(headers)
        sender = extract_sender(headers)
        body = extract_plaintext(payload)

        # Avoid duplicates: check if already in Supabase
        exists = supabase.table("emails").select("id").eq("gmail_id", msg["id"]).execute().data
        if exists:
            continue

        # Insert into Supabase
        supabase.table("emails").insert({
            "user_id": user_email,
            "sender_email": sender,
            "recipient_email": user_email,
            "subject": subject,
            "original_content": body,
            "status": "preprocessing",
            "gmail_id": msg["id"]  # store Gmail msg ID for deduplication
        }).execute()

        logger.info(f"Inserted email for {user_email}: {subject}")

if __name__ == "__main__":
    users = supabase.table("gmail_tokens").select("user_email").execute().data
    for user in users:
        poll_gmail_for_user(user["user_email"])
