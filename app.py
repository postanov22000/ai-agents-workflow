import os
import json
import base64
import hashlib
import logging
from flask import Flask, redirect, request, session, jsonify
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24))

# Configuration
REDIRECT_URI = 'https://replyzeai.onrender.com/oauth2callback'
SCOPES = ["https://www.googleapis.com/auth/gmail.send"]
CLIENT_SECRETS_FILE = "credentials.json"

# Security settings
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

os.makedirs("tokens", exist_ok=True)

@app.before_request
def enforce_https():
    if request.headers.get('X-Forwarded-Proto') == 'http':
        secure_url = request.url.replace('http://', 'https://', 1)
        logger.debug(f"Redirecting to HTTPS: {secure_url}")
        return redirect(secure_url, code=301)

@app.route("/")
def index():
    return '<a href="/authorize">Connect your Gmail</a>'

@app.route("/authorize")
def authorize():
    try:
        state = hashlib.sha256(os.urandom(1024)).hexdigest()
        session["oauth_state"] = state
        
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            redirect_uri=REDIRECT_URI,
            state=state
        )

        auth_url, _ = flow.authorization_url(
            access_type="offline",
            prompt="consent",
            include_granted_scopes="false"  # Critical change
        )

        logger.debug(f"Auth URL: {auth_url}")
        return redirect(auth_url)

    except Exception as e:
        logger.error(f"Authorization error: {str(e)}", exc_info=True)
        return jsonify(error="OAuth initiation failed", details=str(e)), 500

@app.route("/oauth2callback")
def oauth2callback():
    try:
        session_state = session.get("oauth_state")
        request_state = request.args.get('state')
        
        logger.debug(f"State check: {session_state} vs {request_state}")

        if not session_state or session_state != request_state:
            return jsonify(error="Invalid state parameter"), 400

        # Force HTTPS
        authorization_url = request.url.replace('http://', 'https://')
        
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            state=session_state,
            redirect_uri=REDIRECT_URI
        )
        
        flow.fetch_token(authorization_response=authorization_url)
        credentials = flow.credentials
        
        # Scope validation
        granted_scopes = credentials.scopes
        if not set(SCOPES).issubset(granted_scopes):
            logger.error(f"Scope mismatch: {granted_scopes}")
            return jsonify(error="Insufficient permissions granted"), 403

        # Get user info
        service = build("oauth2", "v2", credentials=credentials)
        user_info = service.userinfo().get().execute()
        user_email = user_info['email']
        
        # Store credentials with enforced scopes
        email_hash = hashlib.sha256(user_email.encode()).hexdigest()
        with open(f"tokens/{email_hash}.json", "w") as f:
            json.dump({
                "token": credentials.token,
                "refresh_token": credentials.refresh_token,
                "token_uri": credentials.token_uri,
                "client_id": credentials.client_id,
                "client_secret": credentials.client_secret,
                "scopes": SCOPES  # Enforce original scopes
            }, f)

        session.pop("oauth_state", None)
        return f"Gmail connected successfully for {user_email}!"

    except Exception as e:
        logger.error(f"Callback error: {str(e)}", exc_info=True)
        return jsonify(error="Authentication failed", details=str(e)), 500

@app.route("/send_test_email")
def send_test_email():
    try:
        token_files = os.listdir("tokens")
        if not token_files:
            return "No users connected yet."

        with open(f"tokens/{token_files[0]}", "r") as f:
            creds_data = json.load(f)

        # Enforce scopes when loading credentials
        creds = Credentials.from_authorized_user_info(creds_data, SCOPES)
        service = build("gmail", "v1", credentials=creds)

        message = (
            "From: me\n"
            "To: me\n"
            "Subject: Test Email\n\n"
            "This email was sent successfully!"
        )
        raw = base64.urlsafe_b64encode(message.encode("utf-8")).decode()
        
        result = service.users().messages().send(
            userId="me",
            body={"raw": raw}
        ).execute()

        return f"Email sent! ID: {result['id']}"

    except Exception as e:
        logger.error(f"Email error: {str(e)}", exc_info=True)
        return jsonify(error="Email failed", details=str(e)), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
