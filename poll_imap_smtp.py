# poll_imap_smtp.py

import os
import logging
from supabase import create_client, Client
from fimap import fetch_emails_imap, send_email_smtp
from datetime import datetime
from cryptography.fernet import Fernet

# ── logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("imap_poller")

# ── Supabase client ─────────────────────────────────────────────────────────
SUPABASE_URL              = os.environ["SUPABASE_URL"]
SUPABASE_SERVICE_ROLE_KEY = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
supabase: Client          = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

# ── Fernet cipher ────────────────────────────────────────────────────────────
FERNET_KEY = os.environ["ENCRYPTION_KEY"].encode()
cipher     = Fernet(FERNET_KEY)

def poll_imap():
    # 1) grab users with stored SMTP/IMAP creds
    rows = (
        supabase
        .table("profiles")
        .select("id, smtp_email, smtp_enc_password, imap_host")
        .neq("smtp_email", None)
        .execute()
        .data or []
    )

    for row in rows:
        user_id   = row["id"]
        email_addr= row["smtp_email"]
        imap_host = row.get("imap_host", "imap.gmail.com")

        # decrypt
        try:
            pwd = cipher.decrypt(row["smtp_enc_password"].encode()).decode()
        except Exception as e:
            logger.error(f"Cannot decrypt password for {email_addr}: {e}")
            continue

        logger.info(f"Polling IMAP for {email_addr} (user_id={user_id})")

        try:
            messages = fetch_emails_imap(
                email_addr,
                row["smtp_enc_password"],  # pass the encrypted token; fetch_emails_imap will decrypt
                folder="INBOX",
                imap_host=imap_host
            )
        except Exception:
            logger.exception(f"IMAP fetch failed for {email_addr}@{imap_host}")
            continue

        for msg in messages:
            gmail_id = msg["id"]
            # skip duplicates
            dup = supabase.table("emails").select("id").eq("gmail_id", gmail_id).execute().data
            if dup:
                continue

            supabase.table("emails").insert({
                "user_id":          user_id,
                "sender_email":     msg["from"],
                "recipient_email":  email_addr,
                "subject":          msg["subject"] or "(no subject)",
                "original_content": msg["body"],
                "status":           "processing",
                "gmail_id":         gmail_id,
                "created_at":       datetime.utcnow().isoformat()
            }).execute()

            logger.info(f"Inserted IMAP email {gmail_id} for user {user_id}")

def send_ready_via_smtp():
    ready = (
        supabase
        .table("emails")
        .select("id, user_id, sender_email, processed_content")
        .eq("status", "ready_to_send")
        .execute()
        .data or []
    )

    for rec in ready:
        em_id = rec["id"]
        uid   = rec["user_id"]
        to    = rec["sender_email"]
        body  = rec["processed_content"]

        prof = supabase.table("profiles") \
                       .select("smtp_email, smtp_enc_password, smtp_host") \
                       .eq("id", uid).single().execute().data or {}
        if not prof.get("smtp_email"):
            logger.error(f"No SMTP creds for user {uid}, skipping {em_id}")
            continue

        sender    = prof["smtp_email"]
        encrypted = prof["smtp_enc_password"]
        smtp_host = prof.get("smtp_host", "smtp.gmail.com")

        try:
            send_email_smtp(
                sender,
                encrypted,
                to,
                subject=f"Re: your message",
                body=body,
                smtp_host=smtp_host
            )
            supabase.table("emails") \
                    .update({"status":"sent","sent_at":datetime.utcnow().isoformat()}) \
                    .eq("id", em_id).execute()
            logger.info(f"Sent email {em_id} for user {uid}")
        except Exception as e:
            logger.error(f"Failed to send {em_id}: {e}")
            supabase.table("emails") \
                    .update({"status":"error","error_message":str(e)}) \
                    .eq("id", em_id).execute()

if __name__ == "__main__":
    poll_imap()
    send_ready_via_smtp()
