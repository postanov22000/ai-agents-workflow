import os
import json
import hashlib
from flask import Flask, redirect, request, session, url_for
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "supersecretkey")

SCOPES = [
    "https://www.googleapis.com/auth/userinfo.email",
    "openid",
    "https://www.googleapis.com/auth/gmail.send"
]

CLIENT_SECRETS_FILE = "client_secrets.json"
REDIRECT_URI = "https://replyzeai.onrender.com/oauth2callback"
TOKEN_DIR = "tokens"

if not os.path.exists(TOKEN_DIR):
    os.makedirs(TOKEN_DIR)

def get_token_path(user_email):
    hashed = hashlib.sha256(user_email.encode()).hexdigest()
    return os.path.join(TOKEN_DIR, f"{hashed}.json")

@app.route("/")
def index():
    return '<a href="/authorize">Connect your Gmail</a>'

@app.route("/authorize")
def authorize():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
        include_granted_scopes=True
    )
    auth_url, state = flow.authorization_url(access_type="offline", prompt="consent")
    session["state"] = state
    return redirect(auth_url)

@app.route("/oauth2callback")
def oauth2callback():
    state = session["state"]
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=state,
        redirect_uri=REDIRECT_URI,
        include_granted_scopes=True
    )
    flow.fetch_token(authorization_response=request.url)

    credentials = flow.credentials
    user_info_service = build("oauth2", "v2", credentials=credentials)
    user_info = user_info_service.userinfo().get().execute()

    user_email = user_info["email"]
    token_path = get_token_path(user_email)

    with open(token_path, "w") as token_file:
        token_file.write(credentials.to_json())

    return f"✅ Gmail connected for {user_email}"

@app.route("/send_test_email/<email>")
def send_test_email(email):
    token_path = get_token_path(email)
    if not os.path.exists(token_path):
        return "User not connected", 400

    with open(token_path, "r") as token_file:
        creds_data = json.load(token_file)
        creds = Credentials.from_authorized_user_info(info=creds_data, scopes=SCOPES)

    service = build("gmail", "v1", credentials=creds)
    message = {
        "raw": create_message("me", email, "Hello from ReplyzeAI", "✅ Your Gmail integration is working.")
    }

    service.users().messages().send(userId="me", body=message).execute()
    return "📨 Test email sent!"

def create_message(sender, to, subject, message_text):
    import base64
    from email.mime.text import MIMEText

    message = MIMEText(message_text)
    message["to"] = to
    message["from"] = sender
    message["subject"] = subject
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    return raw

if __name__ == "__main__":
    app.run(debug=True)
