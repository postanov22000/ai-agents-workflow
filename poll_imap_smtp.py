import os
import logging
import re
from supabase import create_client, Client
from fimap import fetch_emails_imap, send_email_smtp
from datetime import datetime
from cryptography.fernet import Fernet


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("imap_poller")

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
fernet = Fernet(ENCRYPTION_KEY.encode()) 

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
# Add these new Environment Variables to your GitHub Secrets/cPanel
ADMIN_EMAIL = os.getenv("ADMIN_INBOUND_EMAIL") 
ADMIN_PASS = os.getenv("ADMIN_INBOUND_PASSWORD")

def poll_central_mailbox():
    """Polls the central mailbox and matches emails to users by various methods"""
    if not ADMIN_EMAIL or not ADMIN_PASS:
        logger.error("Admin inbound credentials not set")
        return

    logger.info(f"Polling central mailbox: {ADMIN_EMAIL}")
    try:
        messages = fetch_emails_imap(
            ADMIN_EMAIL,
            ADMIN_PASS,
            folder="INBOX",
            imap_host="imap.gmail.com",
            imap_port=993
        )

        for msg in messages:
            # Try multiple methods to identify the user
            user_id = None
            to_addr = ""
            
            # Method 1: Check for +tag in recipient (original email)
            raw_to = (msg.get("delivered-to") or msg.get("to") or "").lower()
            clean_to_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', raw_to)
            to_addr = clean_to_match.group(0) if clean_to_match else ""
            
            if to_addr:
                # Check for +tag
                tag_match = re.search(r"\+(.*?)@", to_addr)
                if tag_match:
                    display_name_from_tag = tag_match.group(1)
                    user_id = find_user_by_display_name(display_name_from_tag)
                    if user_id:
                        logger.info(f"Found user via +tag: {display_name_from_tag} -> {user_id}")
            
            # Method 2: Check email body for forwarding patterns
            if not user_id and msg.get("body"):
                body = msg["body"].lower()
                
                # Look for common forwarding patterns
                patterns = [
                    r"forwarded message.*?from:\s*([\w\.-]+@[\w\.-]+\.\w+)",
                    r"begin forwarded message.*?from:\s*([\w\.-]+@[\w\.-]+\.\w+)",
                    r"original message.*?from:\s*([\w\.-]+@[\w\.-]+\.\w+)",
                ]
                
                original_sender = None
                for pattern in patterns:
                    match = re.search(pattern, body, re.IGNORECASE | re.DOTALL)
                    if match:
                        original_sender = match.group(1).lower()
                        break
                
                # Also check for "On [date], [name] <email> wrote:" pattern
                if not original_sender:
                    date_name_pattern = r"on.*?\d{1,2}.*\d{4}.*?([\w\.-]+@[\w\.-]+\.\w+)"
                    match = re.search(date_name_pattern, body, re.IGNORECASE)
                    if match:
                        original_sender = match.group(1).lower()
                
                if original_sender:
                    logger.info(f"Found original sender in forwarded email: {original_sender}")
                    
                    # Try to find user by email (if they have smtp_email set)
                    user_record = supabase.table("profiles").select("id, smtp_email").execute().data or []
                    for profile in user_record:
                        if profile.get("smtp_email", "").lower() == original_sender:
                            user_id = profile["id"]
                            logger.info(f"Matched forwarded email to user by smtp_email: {user_id}")
                            break
            
            # Method 3: Check subject for known patterns
            if not user_id and msg.get("subject"):
                subject = msg.get("subject", "").lower()
                # You could add patterns like "[Username] Inquiry" or similar
            
            if not user_id:
                logger.info(f"Skipping email: Could not identify user for message from {msg.get('from', 'unknown')}")
                continue

            # 5. Duplicate check and Insert
            email_id = msg["id"]
            exists = supabase.table("emails").select("id").eq("gmail_id", email_id).execute().data
            if not exists:
                supabase.table("emails").insert({
                    "user_id": user_id,
                    "sender_email": msg["from"],
                    "recipient_email": to_addr or ADMIN_EMAIL,  # Use admin email if no specific to_addr
                    "subject": msg.get("subject", "(no subject)"),
                    "original_content": msg.get("body", ""),
                    "status": "processing",
                    "gmail_id": email_id,
                    "created_at": datetime.utcnow().isoformat(),
                    "is_forwarded": True  # Mark as forwarded email
                }).execute()
                
                # Increment usage
                supabase.rpc('increment_usage', {
                    'user_id': user_id,
                    'column_name': 'current_month_emails',
                    'amount': 1
                }).execute()
                logger.info(f"Successfully processed forwarded email for user {user_id}")

    except Exception as e:
        logger.error(f"Central mailbox poll failed: {e}")

def find_user_by_display_name(display_name):
    """Helper function to find user by display_name"""
    if not display_name:
        return None
    
    # Get all profiles
    all_profiles = supabase.table("profiles").select("id, display_name").execute().data or []
    
    # Normalize the input display_name
    normalized_input = re.sub(r'[^a-zA-Z0-9]', '', display_name).lower()
    
    for profile in all_profiles:
        profile_display_name = profile.get("display_name", "")
        if profile_display_name:
            # Normalize profile display_name
            normalized_profile = re.sub(r'[^a-zA-Z0-9]', '', profile_display_name).lower()
            
            # Check for match
            if normalized_profile == normalized_input:
                return profile["id"]
    
    return None
# Modified Main Loop
if __name__ == "__main__":
    # 1. Poll individual user IMAPs (Keep this for users who connected their own SMTP)
    poll_imap() 
    
    # 2. NEW: Poll the central mailbox for tagged replies
    poll_central_mailbox() 
    
    # 3. Send outbound
    send_ready_via_smtp()
    process_follow_ups()
