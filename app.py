import os
import json
import hashlib
import logging
from flask import Flask, redirect, request, session
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from werkzeug.exceptions import HTTPException

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24))

# OAuth Configuration
SCOPES = [
    "https://www.googleapis.com/auth/userinfo.email",
    "openid",
    "https://www.googleapis.com/auth/gmail.send"
]
REQUIRED_SCOPES = set(SCOPES)

CLIENT_SECRETS_FILE = "client_secrets.json"
REDIRECT_URI = "https://replyzeai.onrender.com/oauth2callback"
TOKEN_DIR = "tokens"

# Ensure client_secrets.json exists
if not os.path.exists(CLIENT_SECRETS_FILE):
    client_secrets = os.environ.get("GOOGLE_CLIENT_SECRETS")
    if client_secrets:
        with open(CLIENT_SECRETS_FILE, "w") as f:
            f.write(client_secrets)
    else:
        logger.error("Missing client_secrets.json and GOOGLE_CLIENT_SECRETS environment variable")

# Create token directory
os.makedirs(TOKEN_DIR, exist_ok=True)

def get_token_path(user_email):
    return os.path.join(TOKEN_DIR, hashlib.sha256(user_email.encode()).hexdigest() + ".json")

@app.errorhandler(Exception)
def handle_exception(e):
    logger.exception("An error occurred")
    return "Internal Server Error", 500

@app.route("/")
def index():
    return '<a href="/authorize">Connect your Gmail</a>'

@app.route("/authorize")
def authorize():
    try:
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            redirect_uri=REDIRECT_URI
        )
        auth_url, state = flow.authorization_url(
            access_type="offline",
            prompt="consent",
            include_granted_scopes="false",
            scope=' '.join(SCOPES)
        )
        session["state"] = state
        return redirect(auth_url)
    except Exception as e:
        logger.error(f"Authorization error: {str(e)}")
        return "Authorization failed - please try again later", 500

@app.route("/oauth2callback")
def oauth2callback():
    try:
        if "state" not in session:
            return "Missing session state", 400
            
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            state=session["state"],
            redirect_uri=REDIRECT_URI
        )
        
        # Force exact scope matching
        flow.oauth2session.scope = SCOPES
        flow.fetch_token(authorization_response=request.url)
        
        # Validate received scopes
        granted_scopes = set(flow.credentials.scopes)
        if not REQUIRED_SCOPES.issubset(granted_scopes):
            missing = REQUIRED_SCOPES - granted_scopes
            raise ValueError(f"Missing required scopes: {missing}")
            
        if granted_scopes - REQUIRED_SCOPES:
            extra = granted_scopes - REQUIRED_SCOPES
            logger.warning(f"Received extra scopes: {extra}")

        credentials = flow.credentials
        user_info_service = build("oauth2", "v2", credentials=credentials)
        user_info = user_info_service.userinfo().get().execute()
        
        user_email = user_info.get("email")
        if not user_email:
            return "Failed to retrieve user email", 400
            
        # Store credentials
        token_path = get_token_path(user_email)
        with open(token_path, "w") as token_file:
            token_file.write(credentials.to_json())
            
        return f"✅ Gmail connected for {user_email}"
    except Exception as e:
        logger.error(f"OAuth callback error: {str(e)}")
        return "Connection failed - please try again", 500

@app.route("/send_test_email/<email>")
def send_test_email(email):
    try:
        token_path = get_token_path(email)
        if not os.path.exists(token_path):
            return "User not connected", 400
            
        with open(token_path, "r") as token_file:
            creds = Credentials.from_authorized_user_info(
                json.load(token_file), 
                SCOPES
            )
            
        service = build("gmail", "v1", credentials=creds)
        message = {
            "raw": base64.urlsafe_b64encode(
                f"From: me\nTo: {email}\nSubject: Test\n\nHello from ReplyzeAI".encode()
            ).decode()
        }
        service.users().messages().send(userId="me", body=message).execute()
        return "📨 Test email sent!"
    except Exception as e:
        logger.error(f"Test email error: {str(e)}")
        return "Failed to send test email", 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
