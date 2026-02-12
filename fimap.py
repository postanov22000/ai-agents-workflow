import os
import imaplib
import smtplib
import email
from email.mime.text import MIMEText
from cryptography.fernet import Fernet, InvalidToken

FERNET_KEY = os.environ["ENCRYPTION_KEY"].encode()
cipher = Fernet(FERNET_KEY)

# Add email provider detection function
def get_email_settings(email):
    domain = email.split('@')[-1].lower()
    known_providers = {
        "gmail.com": {
            "smtp_host": "smtp.gmail.com",
            "smtp_port": 465,
            "imap_host": "imap.gmail.com",
            "imap_port": 993
        },
        "outlook.com": {
            "smtp_host": "smtp-mail.outlook.com",
            "smtp_port": 587,
            "imap_host": "outlook.office365.com",
            "imap_port": 993
        },
        "yahoo.com": {
            "smtp_host": "smtp.mail.yahoo.com",
            "smtp_port": 465,
            "imap_host": "imap.mail.yahoo.com",
            "imap_port": 993
        },
        # Add more providers as needed
    }
    return known_providers.get(domain, {
        "smtp_host": f"smtp.{domain}",
        "smtp_port": 465,
        "imap_host": f"imap.{domain}",
        "imap_port": 993
    })

def send_email_smtp(from_email, from_password, to_email, subject, body, smtp_host=None, smtp_port=None):
    """
    Sends an email using SMTP. 
    Matches the arguments called in app.py.
    """
    try:
        # Attempt to decrypt the password if it's encrypted
        pwd = cipher.decrypt(from_password.encode()).decode()
    except Exception:
        pwd = from_password

    # Default to Gmail if not provided
    host = smtp_host or "smtp.gmail.com"
    port = smtp_port or 465

    msg = MIMEText(body, "html")
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email

    if port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=15) as server:
            server.login(from_email, pwd)
            server.sendmail(from_email, [to_email], msg.as_string())
    else:
        with smtplib.SMTP(host, port, timeout=15) as server:
            server.starttls()
            server.login(from_email, pwd)
            server.sendmail(from_email, [to_email], msg.as_string())

def fetch_emails_imap(
    email_address: str,
    password_or_token: str,
    folder: str = "INBOX",
    imap_host: str = "imap.gmail.com",
    imap_port: int = 993
):
    try:
        pwd = cipher.decrypt(password_or_token.encode()).decode()
        print(f"[fimap] Decrypted token for {email_address}")
    except (InvalidToken, ValueError):
        pwd = password_or_token

    mail = imaplib.IMAP4_SSL(imap_host, imap_port)
    try:
        mail.login(email_address, pwd)
        mail.select(folder)
        
        status, data = mail.search(None, 'UNSEEN')
        
        messages = []
        for num in data[0].split():
            _, msg_data = mail.fetch(num, '(RFC822)')
            msg = email.message_from_bytes(msg_data[0][1])
            
            # THE CRITICAL FIX: Ensure all headers are captured here
            messages.append({
                "from": msg.get("From"),
                "to": msg.get("To"),
                "delivered-to": msg.get("Delivered-To"),
                "subject": msg.get("Subject"),
                "body": _get_body(msg),
                "in-reply-to": msg.get("In-Reply-To", ""),
                "references": msg.get("References", ""),
                "message-id": msg.get("Message-ID", ""),
                "delivered-to": msg.get("Delivered-To", ""),
                "x-forwarded-to": msg.get("X-Forwarded-To", ""),
                "id": f"{email_address}_{num.decode()}"
            })
        print(f"[fimap] Fetched {len(messages)} messages for {email_address}")
        return messages
    except Exception as e:
        print(f"[fimap] Error: {e}")
        return []
    finally:
        mail.logout()

def _get_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain" and not part.get("Content-Disposition"):
                return part.get_payload(decode=True).decode(errors="ignore")
    return msg.get_payload(decode=True).decode(errors="ignore")



