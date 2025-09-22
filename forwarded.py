# Add to imports section
import email
from email import policy
from email.parser import BytesParser
import quopri
import html
import re
import time
from threading import Thread
from apscheduler.schedulers.background import BackgroundScheduler

# Add these global variables
scheduler = BackgroundScheduler()
processing_active = False

# Add this function to check the dedicated Gmail account
def check_dedicated_gmail_account():
    """Periodically check the dedicated Gmail account for forwarded emails"""
    global processing_active
    
    if processing_active:
        return
        
    processing_active = True
    
    try:
        # Get dedicated account credentials from environment
        dedicated_email = os.environ.get("DEDICATED_GMAIL_EMAIL")
        dedicated_password = os.environ.get("DEDICATED_GMAIL_PASSWORD")
        app_password = os.environ.get("DEDICATED_GMAIL_APP_PASSWORD") or dedicated_password
        
        if not dedicated_email or not app_password:
            app.logger.error("Dedicated Gmail account credentials not configured")
            processing_active = False
            return
            
        # Connect to IMAP
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(dedicated_email, app_password)
        mail.select('inbox')
        
        # Search for unread emails
        status, messages = mail.search(None, 'UNSEEN')
        if status != 'OK':
            app.logger.error("No messages found or error in searching")
            processing_active = False
            return
            
        email_ids = messages[0].split()
        
        for email_id in email_ids:
            try:
                # Fetch the email
                status, msg_data = mail.fetch(email_id, '(RFC822)')
                if status != 'OK':
                    continue
                    
                # Parse the email
                raw_email = msg_data[0][1]
                parsed_email = parse_raw_email(raw_email)
                
                if not parsed_email:
                    continue
                    
                # Extract information
                from_email = parsed_email.get('from')
                to_email = parsed_email.get('to')
                subject = parsed_email.get('subject')
                body = parsed_email.get('body')
                headers = parsed_email.get('headers', {})
                
                # Extract the original recipient from the email body
                original_recipient = extract_original_recipient(body, headers, to_email)
                
                if not original_recipient:
                    app.logger.warning(f"Could not determine original recipient for email from {from_email}")
                    continue
                
                # Find the user based on the original recipient email
                user_resp = supabase.table("profiles") \
                    .select("id, email, ai_enabled, full_name") \
                    .eq("email", original_recipient) \
                    .single() \
                    .execute()
                    
                if not user_resp.data:
                    app.logger.warning(f"No user found for email: {original_recipient}")
                    continue
                    
                user = user_resp.data
                user_id = user["id"]
                
                if not user.get("ai_enabled", False):
                    app.logger.info(f"AI not enabled for user {user_id}")
                    continue
                
                # Check if this is an auto-reply to avoid loops
                auto_submitted = headers.get('auto-submitted', '').lower()
                precedence = headers.get('precedence', '').lower()
                if auto_submitted and auto_submitted != 'no' or precedence == 'bulk' or precedence == 'auto_reply':
                    app.logger.info(f"Ignoring auto-submitted email from {from_email}")
                    continue
                
                # Check if we've already processed this email
                message_id = headers.get('message-id')
                if message_id:
                    existing = supabase.table("emails") \
                        .select("id") \
                        .eq("message_id", message_id) \
                        .execute()
                        
                    if existing.data:
                        app.logger.info(f"Already processed email with Message-ID: {message_id}")
                        continue
                
                # Clean the subject and extract original message
                clean_subject = clean_email_subject(subject)
                original_body = extract_original_message(body, from_email, original_recipient)
                
                # Insert into emails table for processing
                email_data = {
                    "user_id": user_id,
                    "sender_email": from_email,
                    "original_content": original_body,
                    "subject": clean_subject,
                    "status": "processing",
                    "source": "forwarded",
                    "message_id": message_id,
                    "received_at": datetime.now(timezone.utc).isoformat()
                }
                
                result = supabase.table("emails").insert(email_data).execute()
                
                if not result.data:
                    app.logger.error("Failed to insert forwarded email into database")
                    continue
                    
                email_id = result.data[0]["id"]
                app.logger.info(f"Forwarded email stored with ID: {email_id}")
                
                # Immediately trigger processing for this email
                if call_edge("/functions/v1/clever-service/generate-response", {"email_ids": [email_id]}):
                    app.logger.info(f"Successfully triggered processing for email {email_id}")
                else:
                    app.logger.error(f"Failed to trigger processing for email {email_id}")
                    
                # Mark email as processed in dedicated account
                mail.store(email_id, '+FLAGS', '\\Seen')
                
            except Exception as e:
                app.logger.error(f"Error processing email {email_id}: {str(e)}")
                continue
                
        # Close connection
        mail.close()
        mail.logout()
        
    except Exception as e:
        app.logger.error(f"Error checking dedicated Gmail account: {str(e)}")
    
    processing_active = False

# Add helper functions for email parsing
def extract_original_recipient(body, headers, to_email):
    """Extract the original recipient from a forwarded email"""
    try:
        # Check Delivered-To header first
        delivered_to = headers.get('delivered-to') or headers.get('x-original-to')
        if delivered_to:
            return delivered_to.strip()
        
        # Look for the original recipient in the email body
        patterns = [
            r"Originally sent to:?[\s]*([^\s@]+@[^\s@]+\.[^\s@]+)",
            r"Original Recipient:?[\s]*([^\s@]+@[^\s@]+\.[^\s@]+)",
            r"To:?[\s]*([^\s@]+@[^\s@]+\.[^\s@]+)",
            r"begin.*forwarded.*message.*\n.*To:?[\s]*([^\s@]+@[^\s@]+\.[^\s@]+)",
        ]
        
        for pattern in patterns:
            match = re.search(pattern, body, re.IGNORECASE | re.MULTILINE)
            if match:
                return match.group(1).strip()
        
        # If no pattern matched, check if the to_email is a known user email
        user_resp = supabase.table("profiles") \
            .select("id") \
            .eq("email", to_email) \
            .execute()
            
        if user_resp.data:
            return to_email
            
        return None
        
    except Exception as e:
        app.logger.error(f"Error extracting original recipient: {str(e)}")
        return None

def clean_email_subject(subject):
    """Clean email subject by removing common forwarding prefixes"""
    if not subject:
        return "No Subject"
    
    # Remove common forwarding prefixes
    prefixes = ["Fwd:", "Fw:", "RE:", "Re:", "VS:"]
    for prefix in prefixes:
        if subject.startswith(prefix):
            subject = subject[len(prefix):].strip()
    
    return subject

def extract_original_message(body, from_email, original_recipient):
    """Extract the original message from a forwarded email body"""
    try:
        # Common patterns that indicate the start of the original message
        patterns = [
            r"[-]+.*Forwarded message.*[-]+(.*)",
            r"begin.*forwarded.*message(.*)",
            r"[-]+.*Original Message.*[-]+(.*)",
            r"On.*wrote:(.*)",
        ]
        
        for pattern in patterns:
            match = re.search(pattern, body, re.IGNORECASE | re.MULTILINE | re.DOTALL)
            if match:
                return match.group(1).strip()
        
        # If no pattern matched, try to find where the forwarded content begins
        lines = body.split('\n')
        original_start = -1
        
        for i, line in enumerate(lines):
            if re.search(r"forwarded|original.*message|on.*wrote", line, re.IGNORECASE):
                original_start = i + 1
                break
                
        if original_start >= 0:
            return '\n'.join(lines[original_start:]).strip()
        
        # If all else fails, return the entire body
        return body
        
    except Exception as e:
        app.logger.error(f"Error extracting original message: {str(e)}")
        return body

def parse_raw_email(raw_email):
    """Parse raw MIME email data"""
    try:
        # Parse the raw email
        msg = BytesParser(policy=policy.default).parsebytes(raw_email)
        
        # Extract from and to addresses
        from_email = msg['from']
        to_email = msg['to']
        
        # Extract subject
        subject = msg['subject'] or ''
        
        # Extract headers
        headers = {}
        for key, value in msg.items():
            headers[key.lower()] = value
        
        # Extract body text
        body = ""
        if msg.is_multipart():
            for part in msg.iter_parts():
                if part.get_content_type() == 'text/plain':
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        body = payload.decode(charset, errors='replace')
                        break
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or 'utf-8'
                body = payload.decode(charset, errors='replace')
        
        # Handle quoted-printable encoding
        if 'quoted-printable' in msg.get('content-transfer-encoding', '').lower():
            try:
                body = quopri.decodestring(body).decode('utf-8', errors='replace')
            except:
                pass
        
        return {
            "from": from_email,
            "to": to_email,
            "subject": subject,
            "body": body,
            "headers": headers
        }
    except Exception as e:
        app.logger.error(f"Error parsing raw email: {str(e)}")
        return None

# Add a route to setup instructions
@app.route("/email-forwarding-setup")
def email_forwarding_setup():
    """Provide instructions for setting up email forwarding"""
    user_id = request.args.get("user_id")
    if not user_id:
        return "Missing user_id", 400
    
    # Get user's email
    user_resp = supabase.table("profiles") \
        .select("email") \
        .eq("id", user_id) \
        .single() \
        .execute()
    
    if not user_resp.data:
        return "User not found", 404
    
    user_email = user_resp.data["email"]
    dedicated_email = os.environ.get("DEDICATED_GMAIL_EMAIL", "replyzeai.inbound@gmail.com")
    
    return render_template(
        "email_forwarding_setup.html",
        user_id=user_id,
        user_email=user_email,
        dedicated_email=dedicated_email
    )

# Initialize the scheduler when the app starts
@app.before_first_request
def init_scheduler():
    """Initialize the background scheduler to check for emails periodically"""
    try:
        # Check every 5 minutes
        scheduler.add_job(
            func=check_dedicated_gmail_account,
            trigger='interval',
            minutes=5,
            id='email_check_job'
        )
        scheduler.start()
        app.logger.info("Scheduler started for email checking")
    except Exception as e:
        app.logger.error(f"Error starting scheduler: {str(e)}")
