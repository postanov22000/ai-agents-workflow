import os
import logging
from supabase import create_client, Client
from fimap import fetch_emails_imap, send_email_smtp
from datetime import datetime
from cryptography.fernet import Fernet 

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("imap_poller")

# Supabase setup
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

def poll_imap():
    """
    1) Find all users who have SMTP/IMAP creds
    2) Fetch unread messages via IMAP
    3) Insert new ones into `emails`
    """
    rows = (
        supabase
        .table("profiles")
        .select("id, smtp_email, smtp_enc_password, imap_host")
        .neq("smtp_email", None)
        .execute()
        .data
        or []
    )

    key    = os.environ["ENCRYPTION_KEY"].encode()
    cipher = Fernet(key)

    for row in rows:
        user_id   = row["id"]
        email     = row["smtp_email"]
        imap_host = row.get("imap_host", "imap.gmail.com")

        # decrypt
        try:
            pwd = cipher.decrypt(row["smtp_enc_password"].encode()).decode()
        except Exception as e:
            logger.error(f"Cannot decrypt IMAP password for {email}: {e}")
            continue

        logger.info(f"Polling IMAP for {email} (user_id={user_id})")

        try:
            # <-- here’s the fix: use imap_host keyword
            messages = fetch_emails_imap(
                email,
                pwd,
                folder="INBOX",
                imap_host=imap_host
            )
        except Exception:
            logger.exception(f"IMAP fetch failed for {email}@{imap_host}")
            continue

        for msg in messages:
            gmail_id = msg.get("id")
            exists = (
                supabase
                .table("emails")
                .select("id")
                .eq("gmail_id", gmail_id)
                .execute()
                .data
            )
            if exists:
                continue

            supabase.table("emails").insert({
                "user_id":          user_id,
                "sender_email":     msg.get("from", ""),
                "recipient_email":  email,
                "subject":          msg.get("subject", "(no subject)"),
                "original_content": msg.get("body", ""),
                "status":           "processing",
                "gmail_id":         gmail_id,
                "created_at":       datetime.utcnow().isoformat()
            }).execute()

            logger.info(f"Inserted IMAP email {gmail_id} for user {user_id}")

def send_ready_via_smtp():
    """
    1) Find all emails marked `ready_to_send`
    2) Deliver each via send_email_smtp()
    3) Mark them sent in the DB
    """
    ready = supabase.table("emails") \
                    .select("id, user_id, sender_email, processed_content") \
                    .eq("status", "ready_to_send") \
                    .execute().data or []

    key    = os.environ["ENCRYPTION_KEY"].encode()
    cipher = Fernet(key)

    for rec in ready:
        em_id = rec["id"]
        uid   = rec["user_id"]
        to    = rec["sender_email"]
        body  = rec["processed_content"]

        prof = supabase.table("profiles") \
                       .select("smtp_email, smtp_enc_password, smtp_host") \
                       .eq("id", uid).single().execute().data
        if not prof:
            logger.error(f"No SMTP creds for user {uid}, skipping {em_id}")
            continue

        sender    = prof["smtp_email"]
        app_pass  = cipher.decrypt(prof["smtp_enc_password"].encode()).decode()
        smtp_host = prof.get("smtp_host", "smtp.gmail.com")

        try:
            send_email_smtp(sender, app_pass, to, f"Re: your message", body, smtp_host=smtp_host)
            supabase.table("emails") \
                    .update({
                        "status":  "sent",
                        "sent_at": datetime.utcnow().isoformat()
                    }) \
                    .eq("id", em_id).execute()
            logger.info(f"Sent email {em_id} via SMTP for user {uid}")
        except Exception as e:
            logger.error(f"Failed to send {em_id} via SMTP: {e}")
            supabase.table("emails") \
                    .update({
                        "status":        "error",
                        "error_message": str(e)
                    }) \
                    .eq("id", em_id).execute()

if __name__ == "__main__":
    poll_imap()
    send_ready_via_smtp()
