import os
import logging
from supabase import create_client, Client
from fimap import fetch_emails_imap, send_email_smtp
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("imap_poller")

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

def poll_imap():
    rows = (
        supabase
        .table("profiles")
        .select("id, smtp_email, smtp_enc_password, smtp_host, smtp_port, imap_host, imap_port, smtp_folder")
        .neq("smtp_email", None)
        .execute().data or []
    )

    for row in rows:
        user_id = row["id"]
        email_addr = row["smtp_email"]
        
        # Skip if email is empty
        if not email_addr or email_addr.strip() == "":
            logger.error(f"Empty email address for user_id={user_id} - skipping")
            continue
            
        token = row.get("smtp_enc_password") or ""
        smtp_host = row.get("smtp_host", "smtp.gmail.com")
        smtp_port = row.get("smtp_port", 465)
        imap_host = row.get("imap_host", "imap.gmail.com")
        imap_port = row.get("imap_port", 993)
        folder = row.get("smtp_folder", "INBOX")

        if not token:
            logger.error(f"No encrypted password for '{email_addr}' (user_id={user_id}) - skipping")
            continue

        logger.info(f"Polling IMAP for {email_addr} (user_id={user_id}) against {imap_host}:{imap_port}")
        try:
            messages = fetch_emails_imap(
                email_addr,
                token,
                folder=folder,
                imap_host=imap_host,
                imap_port=imap_port
            )
            logger.info(f"Found {len(messages)} messages for {email_addr}")
            
            # Process each message
            for msg in messages:
                email_id = msg["id"]
                # Check if this email already exists in our database
                exists = (
                    supabase
                    .table("emails")
                    .select("id")
                    .eq("gmail_id", email_id)
                    .execute().data
                )
                
                if exists:
                    logger.info(f"Skipping duplicate email {email_id}")
                    continue

                # Insert the new email into the database
                supabase.table("emails").insert({
                    "user_id": user_id,
                    "sender_email": msg["from"],
                    "recipient_email": email_addr,
                    "subject": msg.get("subject", "(no subject)"),
                    "original_content": msg.get("body", ""),
                    "status": "processing",
                    "gmail_id": email_id,
                    "created_at": datetime.utcnow().isoformat()
                }).execute()
                logger.info(f"Inserted IMAP email {email_id} for user {user_id}")
                
        except Exception as e:
            logger.exception(f"IMAP fetch failed for {email_addr}@{imap_host}:{imap_port}: {e}")
            continue

def send_ready_via_smtp():
    ready = supabase.table("emails") \
                    .select("id, user_id, sender_email, processed_content") \
                    .eq("status", "ready_to_send") \
                    .execute().data or []

    for rec in ready:
        em_id = rec["id"]
        uid = rec["user_id"]
        to = rec["sender_email"]
        body = rec["processed_content"] or ""

        prof = supabase.table("profiles") \
                       .select("smtp_email, smtp_enc_password, smtp_host, smtp_port") \
                       .eq("id", uid).single().execute().data or {}

        if not prof.get("smtp_email") or not prof.get("smtp_enc_password"):
            logger.error(f"No SMTP creds for user {uid}, skipping {em_id}")
            continue

        smtp_email = prof["smtp_email"]
        token = prof["smtp_enc_password"]
        smtp_host = prof.get("smtp_host", "smtp.gmail.com")
        smtp_port = prof.get("smtp_port", 465)

        try:
            send_email_smtp(smtp_email, token, to,
                            f"Re: your message", body,
                            smtp_host=smtp_host, smtp_port=smtp_port)
            supabase.table("emails").update({
                "status": "sent",
                "sent_at": datetime.utcnow().isoformat()
            }).eq("id", em_id).execute()
            logger.info(f"Sent email {em_id} via SMTP for user {uid}")
        except Exception as e:
            logger.error(f"SMTP send failed for email {em_id} (user {uid}): {e}")
            supabase.table("emails").update({
                "status": "error",
                "error_message": str(e)
            }).eq("id", em_id).execute()


# Add to poll_imap_smtp.py
def process_follow_ups():
    try:
        # First get due follow-ups
        due_follow_ups = supabase.table("lead_follow_ups") \
            .select("*") \
            .lte("scheduled_at", datetime.utcnow().isoformat()) \
            .eq("status", "processed") \
            .execute().data
        
        if not due_follow_ups:
            logger.info("No due follow-ups to process")
            return
            
        # Get all lead IDs
        lead_ids = [fu["lead_id"] for fu in due_follow_ups]
        
        # Get all leads with their profiles
        leads_with_profiles = supabase.table("leads") \
            .select("*, profiles!inner(*)") \
            .in_("id", lead_ids) \
            .execute().data
        
        # Create a mapping from lead ID to lead data with profile
        lead_profile_map = {lead["id"]: lead for lead in leads_with_profiles}
        
        for follow_up in due_follow_ups:
            try:
                lead_id = follow_up["lead_id"]
                if lead_id not in lead_profile_map:
                    logger.error(f"Lead {lead_id} not found for follow-up {follow_up['id']}")
                    continue
                    
                lead_data = lead_profile_map[lead_id]
                lead = lead_data  # The lead record
                profile = lead_data["profiles"]  # The associated profile
                
                # Get the generated content
                content = follow_up.get("generated_content", "")
                if not content:
                    logger.error(f"No content for follow-up {follow_up['id']}")
                    continue
                
                # Send using existing email infrastructure
                if profile.get("smtp_email") and profile.get("smtp_enc_password"):
                    # Send via SMTP
                    send_email_smtp(
                        profile["smtp_email"],
                        fernet.decrypt(profile["smtp_enc_password"].encode()).decode(),
                        lead["email"],
                        f"Follow-up: {lead['service']} in {lead['city']}",
                        content,
                        smtp_host=profile.get("smtp_host", "smtp.gmail.com")
                    )
                else:
                    # Send via Gmail API (you'll need to implement this)
                    logger.info(f"SMTP not configured for profile {profile['id']}, skipping Gmail API send")
                    continue
                    
                # Mark as sent
                supabase.table("lead_follow_ups") \
                    .update({"status": "sent", "sent_at": datetime.utcnow().isoformat()}) \
                    .eq("id", follow_up["id"]) \
                    .execute()
                    
                logger.info(f"Sent follow-up {follow_up['id']} to {lead['email']}")
                    
            except Exception as e:
                logger.error(f"Failed to send follow-up {follow_up['id']}: {str(e)}")
                supabase.table("lead_follow_ups") \
                    .update({"status": "failed", "error_message": str(e)}) \
                    .eq("id", follow_up["id"]) \
                    .execute()
                    
    except Exception as e:
        logger.error(f"Error in process_follow_ups: {str(e)}")

# Call this function in your main loop
if __name__ == "__main__":
    poll_imap()
    send_ready_via_smtp()
    process_follow_ups()  # Add this line
