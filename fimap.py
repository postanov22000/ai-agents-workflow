# fimap.py

import os
import imaplib
import smtplib
import email
from email.mime.text import MIMEText
from cryptography.fernet import Fernet, InvalidToken

# ── load your one-and-only key from ENV ───────────────────────────────────────
FERNET_KEY = os.environ["ENCRYPTION_KEY"].encode()   # must match how you encrypted them originally
cipher      = Fernet(FERNET_KEY)

# ── SMTP send helper ─────────────────────────────────────────────────────────
def send_email_smtp(
    sender_email: str,
    password_or_token: str,     # can be raw password or fernet token
    recipient: str,
    subject: str,
    body: str,
    smtp_host: str = "smtp.gmail.com",
    smtp_port: int = 465
):
    """
    Send via SMTP SSL.  If `password_or_token` decrypts with Fernet, use that;
    otherwise assume it's already the raw app password.
    """
    pwd = None
    try:
        pwd = cipher.decrypt(password_or_token.encode()).decode()
        # if this succeeds, we just decrypted an encrypted password
    except (InvalidToken, ValueError):
        # not a valid token → assume it's already the plaintext password
        pwd = password_or_token

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"]    = sender_email
    msg["To"]      = recipient

    server = smtplib.SMTP_SSL(smtp_host, smtp_port)
    try:
        server.login(sender_email, pwd)
        server.sendmail(sender_email, [recipient], msg.as_string())
    finally:
        server.quit()

# ── IMAP fetch helper ────────────────────────────────────────────────────────
def fetch_emails_imap(
    email_address: str,
    password_or_token: str,     # can be raw password or fernet token
    folder: str = "INBOX",
    imap_host: str = "imap.gmail.com",
    imap_port: int = 993
):
    """
    Connects via IMAP SSL, returns unread messages.  Same decrypt logic.
    """
    pwd = None
    try:
        pwd = cipher.decrypt(password_or_token.encode()).decode()
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
            body = _get_body(msg)
            messages.append({
                "from":    msg.get("From"),
                "subject": msg.get("Subject"),
                "body":    body,
                "id":      num.decode()
            })
        return messages
    finally:
        mail.logout()

# ── extract plaintext body ─────────────────────────────────────────────────
def _get_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain" and not part.get("Content-Disposition"):
                return part.get_payload(decode=True).decode(errors="ignore")
    return msg.get_payload(decode=True).decode(errors="ignore")
