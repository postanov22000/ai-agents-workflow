import os
import json
import imaplib
import smtplib
import email
from email.mime.text import MIMEText
from flask import Flask, request, session, redirect, url_for, jsonify
from supabase import create_client, Client
from cryptography.fernet import Fernet
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
encryption_key = os.environ.get("ENCRYPTION_KEY")  # 32 url-safe base64
cipher = Fernet(encryption_key)

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ----------------------------------------------------------------------------
# Helpers: IMAP/SMTP
# ----------------------------------------------------------------------------
def send_email_smtp(sender_email: str, encrypted_app_password: str, recipient: str, subject: str, body: str):
    app_password = cipher.decrypt(encrypted_app_password.encode()).decode()
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = recipient

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(sender_email, app_password)
        server.sendmail(sender_email, [recipient], msg.as_string())


def fetch_emails_imap(email_address: str, encrypted_app_password: str, folder: str = "INBOX"):
    app_password = cipher.decrypt(encrypted_app_password.encode()).decode()
    with imaplib.IMAP4_SSL("imap.gmail.com", 993) as mail:
        mail.login(email_address, app_password)
        mail.select(folder)
        status, data = mail.search(None, 'UNSEEN')
        messages = []
        for num in data[0].split():
            _, msg_data = mail.fetch(num, '(RFC822)')
            msg = email.message_from_bytes(msg_data[0][1])
            body = _get_body(msg)
            messages.append({
                'from': msg["From"],
                'subject': msg["Subject"],
                'body': body,
                'id': num.decode()
            })
        return messages


def _get_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                return part.get_payload(decode=True).decode()
    return msg.get_payload(decode=True).decode()

# ----------------------------------------------------------------------------
# Routes: SMTP/IMAP Connect
# ----------------------------------------------------------------------------
@app.route('/connect-smtp', methods=['POST'])
def connect_smtp():
    data = request.json
    email_address = data.get('email')
    app_password = data.get('app_password')
    folder = data.get('folder', 'INBOX')

    if not email_address or not app_password:
        return jsonify({'error': 'Email and app_password required'}), 400

    # Encrypt app password
    encrypted_pw = cipher.encrypt(app_password.encode()).decode()

    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401

    # Upsert credentials in Supabase
    record = {
        'id': user_id,
        'smtp_email': email_address,
        'smtp_enc_password': encrypted_pw,
        'smtp_folder': folder
    }
    res = supabase.table('profiles').upsert(record).execute()

    return jsonify({'message': 'SMTP/IMAP credentials saved'}), 200

# ----------------------------------------------------------------------------
# Example: Sending via fallback
# ----------------------------------------------------------------------------
@app.route('/send', methods=['POST'])
def send():
    data = request.json
    to = data.get('to')
    subject = data.get('subject')
    body = data.get('body')

    user_id = session.get('user_id')
    # Fetch user profile
    profile = supabase.table('profiles').select('*').eq('id', user_id).single().execute().data

    if profile.get('smtp_email') and profile.get('smtp_enc_password'):
        # Use SMTP
        send_email_smtp(
            profile['smtp_email'],
            profile['smtp_enc_password'],
            to, subject, body
        )
    else:
        # Fallback to Gmail API
        creds_data = supabase.table('tokens').select('*').eq('user_id', user_id).single().execute().data
        creds = Credentials.from_authorized_user_info(json.loads(creds_data['credentials']))
        service = build('gmail', 'v1', credentials=creds)
        message = MIMEText(body)
        message['to'] = to
        message['subject'] = subject
        raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
        service.users().messages().send(userId='me', body={'raw': raw}).execute()

    return jsonify({'message': 'Sent'}), 200

# ----------------------------------------------------------------------------
# Example: Fetching via fallback
# ----------------------------------------------------------------------------
@app.route('/fetch', methods=['GET'])
def fetch():
    user_id = session.get('user_id')
    profile = supabase.table('profiles').select('*').eq('id', user_id).single().execute().data

    if profile.get('smtp_email') and profile.get('smtp_enc_password'):
        mails = fetch_emails_imap(
            profile['smtp_email'], profile['smtp_enc_password'], profile.get('smtp_folder', 'INBOX')
        )
    else:
        # Use Gmail API
        creds_data = supabase.table('tokens').select('*').eq('user_id', user_id).single().execute().data
        creds = Credentials.from_authorized_user_info(json.loads(creds_data['credentials']))
        service = build('gmail', 'v1', credentials=creds)
        result = service.users().messages().list(userId='me', q='is:unread').execute()
        mails = []
        for m in result.get('messages', []):
            msg = service.users().messages().get(userId='me', id=m['id'], format='full').execute()
            # extract headers & body (left as exercise)
            mails.append(msg)

    return jsonify({'emails': mails}), 200

# ----------------------------------------------------------------------------
# Run
# ----------------------------------------------------------------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
