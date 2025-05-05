import os
import json
import base64
import hashlib
from flask import Flask, redirect, request, session, url_for
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24))

# Configuration for production
IS_PRODUCTION = os.environ.get('ENVIRONMENT') == 'PRODUCTION'
REDIRECT_URI = 'https://replyzeai.onrender.com/oauth2callback' if IS_PRODUCTION else 'http://localhost:5000/oauth2callback'

SCOPES = ["https://www.googleapis.com/auth/gmail.send"]
CLIENT_SECRETS_FILE = "credentials.json"

os.makedirs("tokens", exist_ok=True)

# Middleware to enforce HTTPS in production
@app.before_request
def enforce_https():
    if IS_PRODUCTION and request.headers.get('X-Forwarded-Proto') == 'http':
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

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
            include_granted_scopes=True,
            prompt="consent",
            state=hashlib.sha256(os.urandom(1024)).hexdigest()  # Enhanced state security
        )
        session["state"] = state
        session.modified = True
        
        # Debug logging
        print(f"Generated auth URL: {auth_url}")
        print(f"Session state stored: {state}")
        
        return redirect(auth_url)
    except Exception as e:
        return f"OAuth flow creation failed: {str(e)}", 500

@app.route("/oauth2callback")
def oauth2callback():
    try:
        state = session.get("state")
        stored_state = session.get("state")
        
        # Debug logging
        print(f"Session state: {stored_state}")
        print(f"Request args: {dict(request.args)}")
        
        if not state or state != request.args.get('state'):
            return "Invalid state parameter", 400

        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            state=state,
            redirect_uri=REDIRECT_URI
        )
        flow.fetch_token(authorization_response=request.url)
        
        credentials = flow.credentials
        service = build("oauth2", "v2", credentials=credentials)
        user_info = service.userinfo().get().execute()
        user_email = user_info["email"]
        
        # Secure token storage
        email_hash = hashlib.sha256(user_email.encode()).hexdigest()
        token_path = f"tokens/{email_hash}.json"
        
        with open(token_path, "w") as f:
            f.write(json.dumps({
                "token": credentials.token,
                "refresh_token": credentials.refresh_token,
                "token_uri": credentials.token_uri,
                "client_id": credentials.client_id,
                "client_secret": credentials.client_secret,
                "scopes": credentials.scopes
            }))
        
        return f"Gmail connected successfully for {user_email}!"
    except Exception as e:
        print(f"OAuth2 callback error: {str(e)}")
        return f"OAuth2 callback failed: {str(e)}", 500

@app.route("/send_test_email")
def send_test_email():
    try:
        token_files = os.listdir("tokens")
        if not token_files:
            return "No users connected yet."

        with open(f"tokens/{token_files[0]}", "r") as f:
            creds_data = json.load(f)

        creds = Credentials.from_authorized_user_info(creds_data, SCOPES)
        service = build("gmail", "v1", credentials=creds)

        # Proper MIME email formatting
        message = (
            "From: me\n"
            "To: me\n"
            "Subject: Hello from Render\n\n"
            "This is a test email sent from Render.com!"
        )
        raw = base64.urlsafe_b64encode(message.encode("utf-8")).decode()
        
        result = service.users().messages().send(
            userId="me",
            body={"raw": raw}
        ).execute()
        
        return f"Email sent! ID: {result['id']}"
    except Exception as e:
        print(f"Email send error: {str(e)}")
        return f"Failed to send test email: {str(e)}", 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
