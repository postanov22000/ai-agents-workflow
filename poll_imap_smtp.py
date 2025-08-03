import os
import logging
from datetime import datetime

from cryptography.fernet import Fernet
from supabase import create_client, Client

from fimap import fetch_emails_imap, send_email_smtp

# ── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("imap_poller")

# ── Supabase setup ───────────────────────────────────────────────────────────
SUPABASE_URL              = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
supabase: Client          = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

# ── Encryption ───────────────────────────────────────────────────────────────
FERNET_KEY = os.environ["ENCRYPTION_KEY"].encode()
cipher     = Fernet(FERNET_KEY)


def poll_imap():
    """
    1) Load every profile with an smtp_email
    2) Skip ones without an encrypted password
    3) Fetch unread via IMAP
    4) Insert new rows into `emails`
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

    for row in rows:
        user_id = row["id"]
        email   = row["smtp_email"]
        enc_pw  = row.get("smtp_enc_password")  # this must match your DB column

        if not enc_pw:
            logger.error(f"No encrypted password for {email!r} (user_id={user_id}) – skipping")
            continue

        # Attempt to decrypt once, to catch totally invalid tokens early
        try:
            _ = cipher.decrypt(enc_pw.encode()).decode()
        except Exception as e:
            logger.error(f"Decryption failed for {email!r} (user_id={user_id}): {e}")
            continue

        imap_host = row.get("imap_host") or "imap.gmail.com"
        logger.info(f"Polling IMAP for {email} (user_id={user_id}) against {imap_host}")

        try:
            # Pass the **encrypted** password into fetch_emails_imap; it will decrypt internally
            messages = fetch_emails_imap(
                email_address     = email,
                encrypted_password= enc_pw,
                folder            = "INBOX",
                imap_host         = imap_host,
                imap_port         = 993
            )
        except Exception as e:
            logger.exception(f"IMAP fetch failed for {email}@{imap_host}: {e}")
            continue

        for msg in messages:
            gmail_id = msg.get("id")
            # skip duplicates
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
    2) Deliver via SMTP fallback (decrypting in fimap.send_email_smtp)
    3) Mark them sent in the DB
    """
    ready = (
        supabase
          .table("emails")
          .select("id, user_id, sender_email, processed_content")
          .eq("status", "ready_to_send")
          .execute()
          .data
        or []
    )

    for rec in ready:
        em_id = rec["id"]
        uid   = rec["user_id"]
        to    = rec["sender_email"]
        body  = rec["processed_content"] or ""

        prof = (
            supabase
              .table("profiles")
              .select("smtp_email, smtp_enc_password, smtp_host")
              .eq("id", uid)
              .single()
              .execute()
              .data
            or {}
        )

        enc_pw = prof.get("smtp_enc_password")
        if not prof.get("smtp_email") or not enc_pw:
            logger.error(f"No SMTP creds for user {uid}, skipping email {em_id}")
            supabase.table("emails") \
                    .update({"status":"error","error_message":"Missing SMTP creds"}) \
                    .eq("id", em_id).execute()
            continue

        try:
            send_email_smtp(
                sender_email      = prof["smtp_email"],
                encrypted_password= enc_pw,
                recipient         = to,
                subject           = "Re: Your Email",
                body              = body,
                smtp_host         = prof.get("smtp_host", "smtp.gmail.com"),
                smtp_port         = 465
            )

            supabase.table("emails") \
                    .update({
                        "status":  "sent",
                        "sent_at": datetime.utcnow().isoformat()
                    }) \
                    .eq("id", em_id).execute()

            logger.info(f"Sent email {em_id} via SMTP for user {uid}")

        except Exception as e:
            logger.error(f"Failed to send {em_id} via SMTP for user {uid}: {e}")
            supabase.table("emails") \
                    .update({
                        "status":        "error",
                        "error_message": str(e)
                    }) \
                    .eq("id", em_id).execute()


if __name__ == "__main__":
    poll_imap()
    send_ready_via_smtp()
