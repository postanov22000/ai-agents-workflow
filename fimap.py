import os
import json
import imaplib
import smtplib
import email
import base64
from email.mime.text import MIMEText
from flask import Flask, request, session, jsonify
from supabase import create_client, Client
from cryptography.fernet import Fernet
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY")

# New (primary) encryption key
NEW_KEY    = os.environ["ENCRYPTION_KEY"].encode()
NEW_CIPHER = Fernet(NEW_KEY)

# Optional old key for rotation
OLD_KEY    = os.environ.get("OLD_ENCRYPTION_KEY")
OLD_CIPHER = Fernet(OLD_KEY.encode()) if OLD_KEY else None

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ----------------------------------------------------------------------------
# Utilities
# ----------------------------------------------------------------------------
def reencrypt_profile(user_id: str, raw_password: str):
    """Rotate this user’s password into the NEW_KEY."""
    encrypted = NEW_CIPHER.encrypt(raw_password.encode()).decode()
    supabase.table("profiles") \
            .update({"smtp_enc_password": encrypted}) \
            .eq("id", user_id) \
            .execute()

def decrypt_password(token: str, user_id: str) -> str:
    """
    Try to decrypt with NEW_CIPHER; if that fails and OLD_CIPHER exists,
    decrypt with OLD_CIPHER then re-encrypt under the new key.
    """
    data = token.encode()
    # 1) Try new key
    try:
        return NEW_CIPHER.decrypt(data).decode()
    except Exception:
        if not OLD_CIPHER:
            raise

    # 2) Fallback to old key
    raw = OLD_CIPHER.decrypt(data).decode()
    # Rotate into the new key for next time
    reencrypt_profile(user_id, raw)
    return raw

# ----------------------------------------------------------------------------
# Helpers: IMAP/SMTP
# ----------------------------------------------------------------------------
def send_email_smtp(sender_email: str,
                    encrypted_app_password: str,
                    recipient: str,
                    subject: str,
                    body: str,
                    smtp_host: str = "smtp.gmail.com"):
    # Determine user_id from session for decryption context
    user_id = session.get("user_id")
    pwd = decrypt_password(encrypted_app_password, user_id)
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"]    = sender_email
    msg["To"]      = recipient

    with smtplib.SMTP_SSL(smtp_host, 465) as server:
        server.login(sender_email, pwd)
        server.sendmail(sender_email, [recipient], msg.as_string())

def _get_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain" and not part.get("Content-Disposition"):
                return part.get_payload(decode=True).decode(errors="ignore")
    return msg.get_payload(decode=True).decode(errors="ignore")

def fetch_emails_imap(email_address: str,
                      encrypted_app_password: str,
                      folder: str = "INBOX",
                      imap_host: str = "imap.gmail.com"):
    user_id = session.get("user_id")
    pwd = decrypt_password(encrypted_app_password, user_id)

    with imaplib.IMAP4_SSL(imap_host, 993) as mail:
        mail.login(email_address, pwd)
        mail.select(folder)
        status, data = mail.search(None, "UNSEEN")
        messages = []
        for num in data[0].split():
            _, msg_data = mail.fetch(num, "(RFC822)")
            msg         = email.message_from_bytes(msg_data[0][1])
            body        = _get_body(msg)
            messages.append({
                "from":    msg.get("From"),
                "subject": msg.get("Subject"),
                "body":    body,
                "id":      num.decode()
            })
        return messages

# ----------------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------------
@app.route("/connect-smtp", methods=["POST"])
def connect_smtp():
    data         = request.json or {}
    email_addr   = data.get("email")
    app_password = data.get("app_password")
    smtp_host    = data.get("smtp_host", "smtp.gmail.com")
    imap_host    = data.get("imap_host", "imap.gmail.com")
    folder       = data.get("folder", "INBOX")

    if not email_addr or not app_password:
        return jsonify({"error": "email & app_password required"}), 400
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "not authenticated"}), 401

    encrypted_pw = NEW_CIPHER.encrypt(app_password.encode()).decode()
    supabase.table("profiles").upsert({
        "id":                 user_id,
        "smtp_email":         email_addr,
        "smtp_enc_password":  encrypted_pw,
        "smtp_host":          smtp_host,
        "imap_host":          imap_host,
        "smtp_folder":        folder
    }).execute()

    return jsonify({"message": "SMTP/IMAP credentials saved"}), 200

@app.route("/send", methods=["POST"])
def send_via_fallback():
    data     = request.json or {}
    to       = data.get("to")
    subject  = data.get("subject")
    body     = data.get("body")
    user_id  = session.get("user_id")

    profile = (supabase.table("profiles")
                      .select("smtp_email,smtp_enc_password,smtp_host")
                      .eq("id", user_id)
                      .single()
                      .execute()
                      .data) or {}

    if profile.get("smtp_email") and profile.get("smtp_enc_password"):
        send_email_smtp(
            profile["smtp_email"],
            profile["smtp_enc_password"],
            to, subject, body,
            smtp_host=profile.get("smtp_host", "smtp.gmail.com")
        )
        return jsonify({"message": "Sent via SMTP"}), 200

    # Fallback to Gmail API
    creds_data = (supabase.table("tokens")
                         .select("credentials")
                         .eq("user_id", user_id)
                         .single()
                         .execute()
                         .data) or {}
    creds = Credentials.from_authorized_user_info(json.loads(creds_data["credentials"]))
    service = build("gmail", "v1", credentials=creds)
    msg     = MIMEText(body)
    msg["to"]      = to
    msg["subject"] = subject
    raw   = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    service.users().messages().send(userId="me", body={"raw": raw}).execute()
    return jsonify({"message": "Sent via Gmail API"}), 200

@app.route("/fetch", methods=["GET"])
def fetch_via_fallback():
    user_id = session.get("user_id")
    profile = (supabase.table("profiles")
                      .select("smtp_email,smtp_enc_password,smtp_folder,imap_host")
                      .eq("id", user_id)
                      .single()
                      .execute()
                      .data) or {}

    if profile.get("smtp_email") and profile.get("smtp_enc_password"):
        mails = fetch_emails_imap(
            profile["smtp_email"],
            profile["smtp_enc_password"],
            folder   = profile.get("smtp_folder", "INBOX"),
            imap_host= profile.get("imap_host",    "imap.gmail.com")
        )
        return jsonify({"emails": mails}), 200

    # Else Gmail API
    creds_data = (supabase.table("tokens")
                         .select("credentials")
                         .eq("user_id", user_id)
                         .single()
                         .execute()
                         .data) or {}
    creds = Credentials.from_authorized_user_info(json.loads(creds_data["credentials"]))
    service = build("gmail", "v1", credentials=creds)
    res     = service.users().messages().list(userId="me", q="is:unread").execute()
    msgs    = []
    for m in res.get("messages", []):
        full = service.users().messages().get(userId="me", id=m["id"], format="full").execute()
        msgs.append(full)
    return jsonify({"emails": msgs}), 200

# ----------------------------------------------------------------------------
# Run (for local testing)
# ----------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
