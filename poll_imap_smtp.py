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
    """Polls the central mailbox and matches emails to users by Display Name or ID."""
    if not ADMIN_EMAIL or not ADMIN_PASS:
        logger.error("Admin inbound credentials not set")
        return

    logger.info(f"Polling central mailbox: {ADMIN_EMAIL}")
    
    # 1. Fetch all profiles to build a Display Name -> ID map
    # This allows us to match 'sophia' from 'sophia@gmail.com' to User ID 123
    try:
        all_profiles = supabase.table("profiles").select("id, display_name, smtp_email").execute().data or []
        
        # Create lookup: 'sophia' -> 'user_uuid'
        name_map = {}
        for p in all_profiles:
            if p.get('display_name'):
                # Store "sophia" key for "Sophia" display name
                name_map[normalize_key(p['display_name'])] = p['id']
                
    except Exception as e:
        logger.error(f"Failed to fetch profiles for name matching: {e}")
        return

    try:
        messages = fetch_emails_imap(
            ADMIN_EMAIL,
            ADMIN_PASS,
            folder="INBOX",
            imap_host="imap.gmail.com",
            imap_port=993
        )

        for msg in messages:
            # 2. Get the address. Priority: Delivered-To -> To
            # If Delivered-To is missing, it will use To (e.g., sophia@gmail.com)
            raw_to = (msg.get("delivered-to") or msg.get("to") or "").lower()
            clean_to_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', raw_to)
            to_addr = clean_to_match.group(0) if clean_to_match else ""
            
            if not to_addr:
                continue

            extracted_user_id = None
            
            # --- MATCHING LOGIC ---
            
            # Extract the "slug" part (e.g., "sophia" from "sophia@gmail.com" OR "admin+sophia@...")
            # If there is a '+' tag, use that. If not, use the part before '@'.
            tag_match = re.search(r"\+(.*)@", to_addr)
            if tag_match:
                candidate_slug = tag_match.group(1)
            else:
                candidate_slug = to_addr.split('@')[0]
                
            clean_slug = normalize_key(candidate_slug)
            
            # A. Try to match the slug against Display Names (e.g. 'sophia' -> User ID)
            if clean_slug in name_map:
                extracted_user_id = name_map[clean_slug]
                logger.info(f"Matched User via Display Name '{clean_slug}': {extracted_user_id}")
            
            # B. If no name match, check if the slug is a UUID (Legacy/Direct ID)
            elif len(clean_slug) > 30: # Simple heuristic for UUID length
                 # Verify if this ID actually exists in our profile list
                 if any(p['id'] == candidate_slug for p in all_profiles):
                     extracted_user_id = candidate_slug
                     logger.info(f"Matched email tag/prefix as User ID: {extracted_user_id}")

            # C. Fallback: Exact email match (e.g., user forwarded from their registered SMTP email)
            if not extracted_user_id:
                match = next((p for p in all_profiles if p.get('smtp_email') == to_addr), None)
                if match:
                    extracted_user_id = match['id']
                    logger.info(f"Matched full email address to user: {extracted_user_id}")

            if not extracted_user_id:
                logger.info(f"Skipping email to {to_addr}: slug '{clean_slug}' did not match any Profile Display Name or ID.")
                continue

            # 3. Duplicate check and Insert
            email_id = msg["id"]
            exists = supabase.table("emails").select("id").eq("gmail_id", email_id).execute().data
            if not exists:
                supabase.table("emails").insert({
                    "user_id": extracted_user_id,
                    "sender_email": msg["from"],
                    "recipient_email": to_addr,
                    "subject": msg.get("subject", "(no subject)"),
                    "original_content": msg.get("body", ""),
                    "status": "processing", # This triggers the generation in your main app loop
                    "gmail_id": email_id,
                    "created_at": datetime.utcnow().isoformat()
                }).execute()
                
                # Increment usage stats
                supabase.rpc('increment_usage', {
                    'user_id': extracted_user_id,
                    'column_name': 'current_month_emails',
                    'amount': 1
                }).execute()
                logger.info(f"Successfully processed email for {extracted_user_id} (Matched: {clean_slug})")

    except Exception as e:
        logger.error(f"Central mailbox poll failed: {e}")

if __name__ == "__main__":
    poll_imap() 
    poll_central_mailbox() 
    send_ready_via_smtp()
    process_follow_ups()
