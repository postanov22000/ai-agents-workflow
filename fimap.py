# fimap.py

import os
import imaplib
import smtplib
import email
from email.mime.text import MIMEText
from cryptography.fernet import Fernet

# ── load your one-and-only key from ENV ───────────────────────────────────────
FERNET_KEY = os.environ["ENCRYPTION_KEY"].encode()
cipher     = Fernet(FERNET_KEY)

# ── SMTP send helper ─────────────────────────────────────────────────────────
def send_email_smtp(
    sender_email: str,
    encrypted_password: str,
    recipient: str,
    subject: str,
    body: str,
    smtp_host: str = "smtp.gmail.com",
    smtp_port: int = 465
):
    """
    Decrypts the stored app password and sends a plain-text email
    via SMTP over SSL.
    """
    if not encrypted_password:
        raise ValueError(f"No SMTP password stored for {sender_email!r}")
    pwd = cipher.decrypt(encrypted_password.encode()).decode()

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"]    = sender_email
    msg["To"]      = recipient

    with smtplib.SMTP_SSL(smtp_host, smtp_port) as server:
        server.login(sender_email, pwd)
        server.sendmail(sender_email, [recipient], msg.as_string())


# ── IMAP fetch helper ────────────────────────────────────────────────────────
def fetch_emails_imap(
    email_address: str,
    encrypted_password: str,
    folder: str       = "INBOX",
    imap_host: str    = "imap.gmail.com",
    imap_port: int    = 993
):
    """
    Decrypts the stored app password, connects via IMAP over SSL,
    and returns a list of unread messages in `folder`. Each message
    is a dict with keys: 'from', 'subject', 'body', 'id'.
    """
    if not encrypted_password:
        raise ValueError(f"No IMAP password stored for {email_address!r}")
    pwd = cipher.decrypt(encrypted_password.encode()).decode()

    with imaplib.IMAP4_SSL(imap_host, imap_port) as mail:
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


# ── extract plaintext body ─────────────────────────────────────────────────
def _get_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if (part.get_content_type() == "text/plain"
               and not part.get("Content-Disposition")):
                return part.get_payload(decode=True).decode(errors="ignore")
    return msg.get_payload(decode=True).decode(errors="ignore")
