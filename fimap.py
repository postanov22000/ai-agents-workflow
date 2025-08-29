# fimap.py
import os
import imaplib
import smtplib
import email
from email.mime.text import MIMEText
from cryptography.fernet import Fernet, InvalidToken
from email_providers import get_email_settings  # Add this import

# ── load your one-and-only key from ENV ───────────────────────────────────────
FERNET_KEY = os.environ["ENCRYPTION_KEY"].encode()
cipher     = Fernet(FERNET_KEY)

def send_email_smtp(
    sender_email: str,
    password_or_token: str,
    recipient: str,
    subject: str,
    body: str,
    smtp_host: str = None,  # Make optional
    smtp_port: int = None,  # Make optional
    smtp_ssl: bool = None,  # Add SSL/TLS parameters
    smtp_tls: bool = None
):
    """
    If `password_or_token` is a valid Fernet token, decrypt it;
    otherwise assume it's already the raw app password.
    """
    try:
        pwd = cipher.decrypt(password_or_token.encode()).decode()
        print(f"[fimap] decrypted token for {sender_email}")
    except (InvalidToken, ValueError):
        pwd = password_or_token
        print(f"[fimap] using plaintext password for {sender_email}")

    # Auto-detect settings if not provided
    if not smtp_host:
        settings = get_email_settings(sender_email)
        if settings:
            smtp_host = settings.get("smtp_host", "smtp.gmail.com")
            smtp_port = settings.get("smtp_port", 587)
            smtp_ssl = settings.get("smtp_ssl", False)
            smtp_tls = settings.get("smtp_tls", True)
        else:
            # Fallback to Gmail
            smtp_host = "smtp.gmail.com"
            smtp_port = 587
            smtp_ssl = False
            smtp_tls = True

    is_html = "<" in body and ">" in body
    subtype = "html" if is_html else "plain"
    msg = MIMEText(body, subtype)
    msg["Subject"] = subject
    msg["From"]    = sender_email
    msg["To"]      = recipient

    # Handle different connection types
    if smtp_ssl:
        with smtplib.SMTP_SSL(smtp_host, smtp_port) as server:
            server.login(sender_email, pwd)
            server.sendmail(sender_email, [recipient], msg.as_string())
    else:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            if smtp_tls:
                server.starttls()
            server.login(sender_email, pwd)
            server.sendmail(sender_email, [recipient], msg.as_string())
            
    print(f"[fimap] SMTP send succeeded for {sender_email} → {recipient}")

def fetch_emails_imap(
    email_address: str,
    password_or_token: str,
    folder: str = "INBOX",
    imap_host: str = None,  # Make optional
    imap_port: int = None,  # Make optional
    imap_ssl: bool = None   # Add SSL parameter
):
    """
    Returns a list of unread messages dicts.  Same decrypt logic.
    """
    try:
        pwd = cipher.decrypt(password_or_token.encode()).decode()
        print(f"[fimap] decrypted token for IMAP {email_address}")
    except (InvalidToken, ValueError):
        pwd = password_or_token
        print(f"[fimap] using plaintext password for IMAP {email_address}")

    # Auto-detect settings if not provided
    if not imap_host:
        settings = get_email_settings(email_address)
        if settings:
            imap_host = settings.get("imap_host", "imap.gmail.com")
            imap_port = settings.get("imap_port", 993)
            imap_ssl = settings.get("imap_ssl", True)
        else:
            # Fallback to Gmail
            imap_host = "imap.gmail.com"
            imap_port = 993
            imap_ssl = True

    if imap_ssl is None:
        imap_ssl = True

    
    if imap_ssl:
        mail = imaplib.IMAP4_SSL(imap_host, imap_port)
    else:
        mail = imaplib.IMAP4(imap_host, imap_port)
        
    try:
        mail.login(email_address, pwd)
        mail.select(folder)
        status, data = mail.search(None, 'UNSEEN')
        messages = []
        for num in data[0].split():
            _, msg_data = mail.fetch(num, '(RFC822)')
            msg = email.message_from_bytes(msg_data[0][1])
            messages.append({
                "from":    msg.get("From"),
                "subject": msg.get("Subject"),
                "body":    _get_body(msg),
                "id":      num.decode()
            })
        print(f"[fimap] fetched {len(messages)} messages for {email_address}")
        return messages
    finally:
        mail.logout()

def _get_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain" and not part.get("Content-Disposition"):
                return part.get_payload(decode=True).decode(errors="ignore")
    return msg.get_payload(decode=True).decode(errors="ignore")
