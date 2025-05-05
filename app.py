import os
import json
import base64
import hashlib
import logging
from flask import Flask, redirect, request, session, url_for, jsonify
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24))

# Hardcode production settings for Render
IS_PRODUCTION = True  # Force production mode
REDIRECT_URI = 'https://replyzeai.onrender.com/oauth2callback'
SCOPES = ["https://www.googleapis.com/auth/gmail.send"]
CLIENT_SECRETS_FILE = "credentials.json"

# Security headers middleware
@app.after_request
def add_security_headers(response):
    if IS_PRODUCTION:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

@app.before_request
def enforce_https():
    if IS_PRODUCTION and request.headers.get('X-Forwarded-Proto') == 'http':
        secure_url = request.url.replace('http://', 'https://', 1)
        logger.debug(f"Redirecting to HTTPS: {secure_url}")
        return redirect(secure_url, code=301)

@app.route("/")
def index():
    return '<a href="/authorize">Connect your Gmail</a>'

@app.route("/authorize")
def authorize():
    try:
        # Generate unique state with session ID binding
        state = hashlib.sha256(
            f"{os.urandom(1024)}{session.sid}".encode()
        ).hexdigest()
        
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            redirect_uri=REDIRECT_URI,
            state=state
        )
        
        auth_url, _ = flow.authorization_url(
            access_type="offline",
            prompt="consent",
            include_granted_scopes="true"
        )
        
        session["oauth_state"] = state
        session.modified = True
        
        logger.debug(f"""
        Authorization initiated:
        - State: {state}
        - Auth URL: {auth_url}
        - Session ID: {session.sid}
        """)
        
        return redirect(auth_url)
        
    except Exception as e:
        logger.error(f"Authorization error: {str(e)}", exc_info=True)
        return jsonify(error="OAuth initiation failed", details=str(e)), 500

@app.route("/oauth2callback")
def oauth2callback():
    try:
        # Get state from session and request
        session_state = session.get("oauth_state")
        request_state = request.args.get('state')
        error = request.args.get('error')
        
        logger.debug(f"""
        Callback received:
        - Session State: {session_state}
        - Request State: {request_state}
        - Error: {error}
        - Full Args: {dict(request.args)}
        """)
        
        # Check for OAuth errors
        if error:
            return jsonify(error="OAuth provider error", details=error), 400
            
        # Validate state parameter
        if not session_state or session_state != request_state:
            logger.error(f"State mismatch: Session({session_state}) vs Request({request_state})")
            return jsonify(error="Invalid state parameter"), 400
            
        # Initialize flow with correct parameters
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            state=session_state,
            redirect_uri=REDIRECT_URI
        )
        
        # Full URL reconstruction for Render
        authorization_response = request.url.replace('http://', 'https://')
        flow.fetch_token(authorization_response=authorization_response)
        
        # Get user info
        credentials = flow.credentials
        service = build("oauth2", "v2", credentials=credentials)
        user_info = service.userinfo().get().execute()
        user_email = user_info['email']
        
        # Secure token storage
        email_hash = hashlib.sha256(user_email.encode()).hexdigest()
        token_path = f"tokens/{email_hash}.json"
        
        with open(token_path, "w") as f:
            json.dump({
                "token": credentials.token,
                "refresh_token": credentials.refresh_token,
                "token_uri": credentials.token_uri,
                "client_id": credentials.client_id,
                "client_secret": credentials.client_secret,
                "scopes": credentials.scopes
            }, f)
        
        logger.info(f"Successful authentication for {user_email}")
        return f"Gmail connected successfully for {user_email}!"
        
    except Exception as e:
        logger.error(f"Callback error: {str(e)}", exc_info=True)
        return jsonify(error="Authentication failed", details=str(e)), 500

@app.route("/send_test_email")
def send_test_email():
    try:
        # Existing implementation
        pass
    except Exception as e:
        logger.error(f"Email send error: {str(e)}", exc_info=True)
        return jsonify(error="Email failed", details=str(e)), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
