# poll_imap_smtp.py

import os
import logging
from supabase import create_client, Client
from fimap import fetch_emails_imap, send_email_smtp
from datetime import datetime
from cryptography.fernet import Fernet 

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("imap_poller")

# Supabase setup (same as before)…
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

def poll_imap():
    rows = supabase.table("profiles") \
                   .select("id, smtp_email, smtp_enc_password") \
                   .not_("smtp_email", "is", None) \
                   .execute().data or []

    for row in rows:
        user_id = row["id"]
        email   = row["smtp_email"]

        # decrypt password
        from cryptography.fernet import Fernet
        key = os.environ["ENCRYPTION_KEY"].encode()
        f   = Fernet(key)
        try:
            pwd = f.decrypt(row["smtp_enc_password"].encode()).decode()
        except Exception as e:
            logger.error(f"Failed to decrypt password for {email}: {e}", exc_info=True)
            continue

        logger.info(f"Polling IMAP for {email} (user_id={user_id})")
        try:
            messages = fetch_emails_imap(email, pwd)
        except Exception as e:
            # Log full exception and traceback
            logger.error(f"IMAP fetch failed for {email}: {e}", exc_info=True)
            continue

        for msg in messages:
            gmail_id = msg.get("id")
            if not gmail_id:
                logger.warning(f"Skipping IMAP message with no ID for {email}")
                continue

            # Skip duplicates
            exists = supabase.table("emails") \
                             .select("id") \
                             .eq("gmail_id", gmail_id) \
                             .execute().data
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
    2) Load that user’s SMTP creds
    3) Deliver each via send_email_smtp()
    4) Mark them sent in the DB
    """
    ready = supabase.table("emails") \
                    .select("id, user_id, sender_email, processed_content") \
                    .eq("status", "ready_to_send") \
                    .execute().data or []

    for rec in ready:
        em_id = rec["id"]
        uid   = rec["user_id"]
        to    = rec["sender_email"]
        body  = rec["processed_content"]

        # load creds again
        prof = supabase.table("profiles") \
                       .select("smtp_email, smtp_enc_password") \
                       .eq("id", uid).single().execute().data
        if not prof:
            logger.error(f"No SMTP creds for user {uid}, skipping {em_id}")
            continue

        email = prof["smtp_email"]
        pwd   = Fernet(os.environ["ENCRYPTION_KEY"].encode()) \
                  .decrypt(prof["smtp_enc_password"].encode()).decode()

        try:
            send_email_smtp(email, pwd, to, f"Re: your message", body)
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
