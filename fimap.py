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

def send_email_smtp(sender_email, password_or_token, recipient, subject, body, smtp_host=None, smtp_port=None):
    try:
        pwd = cipher.decrypt(password_or_token.encode()).decode()
    except (InvalidToken, ValueError):
        pwd = password_or_token

    # Get settings if not provided
    if not smtp_host or not smtp_port:
        settings = get_email_settings(sender_email)
        smtp_host = settings["smtp_host"]
        smtp_port = settings["smtp_port"]

    is_html = "<" in body and ">" in body
    subtype = "html" if is_html else "plain"
    msg = MIMEText(body, subtype)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = recipient

    # Use SSL for ports 465, TLS for 587
    if smtp_port == 465:
        with smtplib.SMTP_SSL(smtp_host, smtp_port) as server:
            server.login(sender_email, pwd)
            server.sendmail(sender_email, [recipient], msg.as_string())
    else:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(sender_email, pwd)
            server.sendmail(sender_email, [recipient], msg.as_string())

def fetch_emails_imap(email_address, password_or_token, folder="INBOX", imap_host=None, imap_port=None):
    try:
        pwd = cipher.decrypt(password_or_token.encode()).decode()
    except (InvalidToken, ValueError):
        pwd = password_or_token

    # Get settings if not provided
    if not imap_host or not imap_port:
        settings = get_email_settings(email_address)
        imap_host = settings["imap_host"]
        imap_port = settings["imap_port"]

    mail = imaplib.IMAP4_SSL(imap_host, imap_port)
    try:
        mail.login(email_address, pwd)
        mail.select(folder)
        status, data = mail.search(None, 'UNSEEN')
        messages = []
        for num in data[0].split():
            _, msg_data = mail.fetch(num, '(RFC822)')
            msg = email.message_from_bytes(msg_data[0][1])
            messages.append({
                "from": msg.get("From"),
                "to": msg.get("To"),
                "delivered-to": msg.get("Delivered-To"),
                "subject": msg.get("Subject"),
                "body": _get_body(msg),
                "id": f"{email_address}_{num.decode()}"
            })
        return messages
    finally:
        mail.logout()

def _get_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain" and not part.get("Content-Disposition"):
                return part.get_payload(decode=True).decode(errors="ignore")
    return msg.get_payload(decode=True).decode(errors="ignore")



def fetch_emails_imap(
    email_address: str,
    password_or_token: str,
    folder: str = "INBOX",
    imap_host: str = "imap.gmail.com",
    imap_port: int = 993
):
    try:
        pwd = cipher.decrypt(password_or_token.encode()).decode()
        print(f"[fimap] decrypted token for IMAP {email_address}")
    except (InvalidToken, ValueError):
        pwd = password_or_token
        print(f"[fimap] using plaintext password for IMAP {email_address}")

    mail = imaplib.IMAP4_SSL(imap_host, imap_port)
    try:
        print(f"[fimap] Connecting to {imap_host}:{imap_port}")
        mail.login(email_address, pwd)
        print(f"[fimap] Logged in successfully")
        mail.select(folder)
        print(f"[fimap] Selected folder: {folder}")
        
        status, data = mail.search(None, 'UNSEEN')
        print(f"[fimap] Search status: {status}, data: {data}")
        
        messages = []
        for num in data[0].split():
            print(f"[fimap] Processing message {num}")
            _, msg_data = mail.fetch(num, '(RFC822)')
            msg = email.message_from_bytes(msg_data[0][1])
            messages.append({
                "from": msg.get("From"),
                "subject": msg.get("Subject"),
                "body": _get_body(msg),
                "id": num.decode()
            })
        print(f"[fimap] fetched {len(messages)} messages for {email_address}")
        return messages
    except Exception as e:
        print(f"[fimap] Error: {e}")
        return []
    finally:
        mail.logout()
