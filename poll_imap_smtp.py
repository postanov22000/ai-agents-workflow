import os
import logging
from supabase import create_client, Client
from fimap import fetch_emails_imap, send_email_smtp
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("imap_poller")

SUPABASE_URL             = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY= os.getenv("SUPABASE_SERVICE_ROLE_KEY")
ENCRYPTION_KEY           = os.getenv("ENCRYPTION_KEY")  # not used here
supabase: Client         = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

def poll_imap():
    rows = (
        supabase
        .table("profiles")
        .select("id, smtp_email, smtp_enc_password, smtp_host, smtp_folder, imap_host")
        .neq("smtp_email", None)
        .execute().data or []
    )

    for row in rows:
        user_id = row["id"]
        email_addr = row["smtp_email"]
        token      = row.get("smtp_enc_password") or ""
        imap_host  = row.get("imap_host", "imap.gmail.com")
        folder     = row.get("smtp_folder", "INBOX")

        if not token:
            logger.error(f"No encrypted password for '{email_addr}' (user_id={user_id}) – skipping")
            continue

        logger.info(f"Polling IMAP for {email_addr} (user_id={user_id}) against {imap_host}")
        try:
            messages = fetch_emails_imap(
                email_addr,
                token,
                folder=folder,
                imap_host=imap_host
            )
        except Exception as e:
            logger.exception(f"IMAP fetch failed for {email_addr}@{imap_host}: {e}")
            continue

        for msg in messages:
            gmail_id = msg["id"]
            exists = (
                supabase
                .table("emails")
                .select("id")
                .eq("gmail_id", gmail_id)
                .execute().data
            )
            if exists:
                logger.info(f"Skipping duplicate {gmail_id}")
                continue

            supabase.table("emails").insert({
                "user_id":          user_id,
                "sender_email":     msg["from"],
                "recipient_email":  email_addr,
                "subject":          msg.get("subject", "(no subject)"),
                "original_content": msg.get("body", ""),
                "status":           "processing",
                "gmail_id":         gmail_id,
                "created_at":       datetime.utcnow().isoformat()
            }).execute()
            logger.info(f"Inserted IMAP email {gmail_id} for user {user_id}")

def send_ready_via_smtp():
    ready = supabase.table("emails") \
                    .select("id, user_id, sender_email, processed_content") \
                    .eq("status", "ready_to_send") \
                    .execute().data or []

    for rec in ready:
        em_id = rec["id"]
        uid   = rec["user_id"]
        to    = rec["sender_email"]
        body  = rec["processed_content"] or ""

        prof = supabase.table("profiles") \
                       .select("smtp_email, smtp_enc_password, smtp_host") \
                       .eq("id", uid).single().execute().data or {}

        if not prof.get("smtp_email") or not prof.get("smtp_enc_password"):
            logger.error(f"No SMTP creds for user {uid}, skipping {em_id}")
            continue

        smtp_email = prof["smtp_email"]
        token      = prof["smtp_enc_password"]
        smtp_host  = prof.get("smtp_host", "smtp.gmail.com")

        try:
            send_email_smtp(smtp_email, token, to,
                            f"Re: your message", body,
                            smtp_host=smtp_host)
            supabase.table("emails").update({
                "status":  "sent",
                "sent_at": datetime.utcnow().isoformat()
            }).eq("id", em_id).execute()
            logger.info(f"Sent email {em_id} via SMTP for user {uid}")
        except Exception as e:
            logger.error(f"SMTP send failed for email {em_id} (user {uid}): {e}")
            supabase.table("emails").update({
                "status":        "error",
                "error_message": str(e)
            }).eq("id", em_id).execute()

if __name__ == "__main__":
    poll_imap()
    send_ready_via_smtp()
