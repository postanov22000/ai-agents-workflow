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
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "supersecretkey")

SCOPES = ["https://www.googleapis.com/auth/gmail.send"]
CLIENT_SECRETS_FILE = "credentials.json"

os.makedirs("tokens", exist_ok=True)

@app.route("/")
def index():
    return '<a href="/authorize">Connect your Gmail</a>'

@app.route("/authorize")
def authorize():
    try:
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            redirect_uri=url_for("oauth2callback", _external=True)
        )
        auth_url, state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes=False,
            prompt="consent"
        )
        session["state"] = state
        return redirect(auth_url)
    except Exception as e:
        return f"OAuth flow creation failed: {e}"

@app.route("/oauth2callback")
def oauth2callback():
    try:
        state = session.get("state")
        if not state:
            return "Missing session state"

        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            state=state,
            redirect_uri=url_for("oauth2callback", _external=True)
        )
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials

        # Use email hash as a safe filename
        service = build("oauth2", "v2", credentials=credentials)
        user_info = service.userinfo().get().execute()
        user_email = user_info["email"]
        email_hash = hashlib.sha256(user_email.encode()).hexdigest()
        token_path = f"tokens/{email_hash}.json"

        with open(token_path, "w") as f:
            f.write(credentials.to_json())

        return f"Gmail connected successfully for {user_email}!"
    except Exception as e:
        return f"OAuth2 callback failed: {e}"

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

        message = {
            "raw": base64.urlsafe_b64encode(
                b"From: me\nTo: me\nSubject: Hello\n\nHello world!"
            ).decode()
        }

        result = service.users().messages().send(userId="me", body=message).execute()
        return f"Email sent! ID: {result['id']}"
    except Exception as e:
        return f"Failed to send test email: {e}"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
