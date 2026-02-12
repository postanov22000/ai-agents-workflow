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

# --- NEW HELPER: Normalize names for matching ---
def normalize_key(text):
    """Converts 'Sophia' or 'Sophia!' to 'sophia' for robust matching."""
    if not text:
        return ""
    return re.sub(r'[^a-z0-9]', '', text.lower())

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
            
            for msg in messages:
                email_id = msg["id"]
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

def process_follow_ups():
    try:
        due_follow_ups = supabase.table("lead_follow_ups") \
            .select("*") \
            .lte("scheduled_at", datetime.utcnow().isoformat()) \
            .eq("status", "processed") \
            .execute().data
        
        if not due_follow_ups:
            logger.info("No due follow-ups to process")
            return
            
        lead_ids = [fu["lead_id"] for fu in due_follow_ups]
        
        leads_with_profiles = supabase.table("leads") \
            .select("*, profiles!inner(*)") \
            .in_("id", lead_ids) \
            .execute().data
        
        lead_profile_map = {lead["id"]: lead for lead in leads_with_profiles}
        
        for follow_up in due_follow_ups:
            try:
                lead_id = follow_up["lead_id"]
                if lead_id not in lead_profile_map:
                    logger.error(f"Lead {lead_id} not found for follow-up {follow_up['id']}")
                    continue
                    
                lead_data = lead_profile_map[lead_id]
                lead = lead_data
                profile = lead_data["profiles"]
                
                content = follow_up.get("generated_content", "")
                if not content:
                    logger.error(f"No content for follow-up {follow_up['id']}")
                    continue
                
                if profile.get("smtp_email") and profile.get("smtp_enc_password"):
                    send_email_smtp(
                        profile["smtp_email"],
                        fernet.decrypt(profile["smtp_enc_password"].encode()).decode(),
                        lead["email"],
                        f"Follow-up: {lead['service']} in {lead['city']}",
                        content,
                        smtp_host=profile.get("smtp_host", "smtp.gmail.com")
                    )
                else:
                    logger.info(f"SMTP not configured for profile {profile['id']}, skipping Gmail API send")
                    continue
                    
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

ADMIN_EMAIL = os.getenv("ADMIN_INBOUND_EMAIL") 
ADMIN_PASS = os.getenv("ADMIN_INBOUND_PASSWORD")

def poll_central_mailbox():
    """Polls the central mailbox and matches emails to users by tag, email address, OR conversation thread"""
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

        logger.info(f"Found {len(messages)} messages in central mailbox")

        for msg in messages:
            logger.debug(f"Processing message ID: {msg.get('id')}")
            
            # Check for duplicate first
            email_id = msg["id"]
            exists = supabase.table("emails").select("id").eq("gmail_id", email_id).execute().data
            if exists:
                logger.info(f"Skipping duplicate email {email_id}")
                continue
            
            # Get sender for matching
            sender_email = msg.get("from", "").lower()
            
            extracted_user_id = None
            is_reply = False
            
            # --- STRATEGY 1: Check if this is a REPLY to an existing conversation ---
            # Look for In-Reply-To or References headers (conversation threading)
            in_reply_to = msg.get("in-reply-to", "").strip()
            references = msg.get("references", "").strip()
            
            logger.info(f"Checking for conversation thread - In-Reply-To: {in_reply_to}, References: {references}")
            
            # Try to find existing conversation by sender email
            if sender_email:
                logger.info(f"Looking for existing conversation with sender: {sender_email}")
                
                # Find the most recent email FROM this user (where they were the sender)
                # This is their original inquiry that we replied to
                existing_conversation = supabase.table("emails") \
                    .select("user_id, id") \
                    .eq("sender_email", sender_email) \
                    .order("created_at", desc=True) \
                    .limit(1) \
                    .execute().data
                
                if existing_conversation:
                    extracted_user_id = existing_conversation[0]["user_id"]
                    is_reply = True
                    logger.info(f"✅ Found existing conversation! Matched to user_id: {extracted_user_id}")
                    logger.info(f"This is a REPLY in an ongoing conversation")
            
            # --- STRATEGY 2: Extract from recipient email (original logic) ---
            if not extracted_user_id:
                raw_recipient = (
                    msg.get("x-forwarded-to") or 
                    msg.get("delivered-to") or 
                    msg.get("to") or 
                    ""
                ).lower()
                
                logger.debug(f"Raw recipient from headers: {raw_recipient}")
                
                # Extract email address
                email_match = re.search(r'[\w\.+-]+@[\w\.-]+\.\w+', raw_recipient)
                if not email_match:
                    logger.info(f"No valid email found in recipient header: {raw_recipient}")
                    continue
                    
                recipient_email = email_match.group(0)
                logger.info(f"Extracted recipient email: {recipient_email}")
                
                # CASE 1: Extract from +tag in email address
                if "+" in recipient_email:
                    tag_match = re.search(r'\+(.+?)(?:@|$)', recipient_email)
                    if tag_match:
                        tag_value = tag_match.group(1)
                        logger.info(f"Found +tag in email: {tag_value}")
                        
                        tag_value = tag_value.split('@')[0]
                        
                        # Check if tag is a UUID
                        if len(tag_value) > 30 and '-' in tag_value:
                            logger.info(f"Checking if tag '{tag_value}' is a valid UUID")
                            user_by_id = supabase.table("profiles").select("id").eq("id", tag_value).execute().data
                            if user_by_id:
                                extracted_user_id = tag_value
                                logger.info(f"✅ Matched +tag as UUID: {extracted_user_id}")
                        else:
                            # Try to match by display name (normalized)
                            normalized_tag = re.sub(r'[^a-z0-9]', '', tag_value.lower())
                            logger.info(f"Looking for display name match for tag: {normalized_tag}")
                            
                            profiles = supabase.table("profiles").select("id, display_name").execute().data or []
                            for profile in profiles:
                                if profile.get("display_name"):
                                    normalized_name = re.sub(r'[^a-z0-9]', '', profile["display_name"].lower())
                                    if normalized_name == normalized_tag:
                                        extracted_user_id = profile["id"]
                                        logger.info(f"✅ Matched +tag '{tag_value}' to display name '{profile['display_name']}' (ID: {extracted_user_id})")
                                        break
                            
                            # If no display name match, try email prefix
                            if not extracted_user_id:
                                user_by_email = supabase.table("profiles").select("id").eq("smtp_email", f"{tag_value}@").like("smtp_email", f"{tag_value}@%").execute().data
                                if user_by_email:
                                    extracted_user_id = user_by_email[0]["id"]
                                    logger.info(f"✅ Matched +tag '{tag_value}' to email prefix: {extracted_user_id}")
                
                # CASE 2: Direct email match
                if not extracted_user_id:
                    logger.info(f"Checking direct email match for: {recipient_email}")
                    user_record = supabase.table("profiles").select("id").eq("smtp_email", recipient_email).execute().data
                    if user_record:
                        extracted_user_id = user_record[0]["id"]
                        logger.info(f"✅ Direct email match: {extracted_user_id}")

            # Final check: do we have a user?
            if not extracted_user_id:
                logger.warning(f"❌ Skipping email from {sender_email}: No user match found")
                logger.warning(f"Hint: Make sure the client has an existing conversation or the email has proper routing tags")
                continue

            # Insert the email
            try:
                # Determine recipient email - use the agent's email if we found them
                if extracted_user_id:
                    agent_profile = supabase.table("profiles").select("smtp_email").eq("id", extracted_user_id).single().execute().data
                    recipient_email = agent_profile.get("smtp_email") if agent_profile else recipient_email
                
                insert_data = {
                    "user_id": extracted_user_id,
                    "sender_email": sender_email,
                    "recipient_email": recipient_email,
                    "subject": msg.get("subject", "(no subject)"),
                    "original_content": msg.get("body", "[No content]"),
                    "status": "processing",
                    "gmail_id": email_id,
                    "is_follow_up": is_reply,  # Mark if this is a reply
                    "created_at": datetime.utcnow().isoformat()
                }
                
                logger.info(f"Inserting email: sender={sender_email}, user_id={extracted_user_id}, is_reply={is_reply}")
                
                result = supabase.table("emails").insert(insert_data).execute()
                logger.info(f"✅ Email inserted successfully")
                
                # Try to increment usage
                try:
                    supabase.rpc('increment_usage', {
                        'user_id': extracted_user_id,
                        'column_name': 'current_month_emails',
                        'amount': 1
                    }).execute()
                    logger.info(f"✅ Incremented usage for user {extracted_user_id}")
                except Exception as rpc_error:
                    logger.warning(f"⚠️ Failed to increment usage (email still inserted): {rpc_error}")
                    
            except Exception as insert_error:
                logger.error(f"❌ Failed to insert email: {insert_error}")
                import traceback
                traceback.print_exc()

    except Exception as e:
        logger.error(f"❌ Central mailbox poll failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    poll_imap() 
    poll_central_mailbox() 
    send_ready_via_smtp()
    process_follow_ups()
