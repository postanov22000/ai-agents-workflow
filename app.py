import os
import json
import base64
from flask import Flask, redirect, request, session, url_for
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "supersecretkey")

SCOPES = ["https://www.googleapis.com/auth/gmail.send", "https://www.googleapis.com/auth/gmail.modify"]
REDIRECT_URI = "https://replyzeai.onrender.com/oauth2callback"

# Set this if you use env vars instead of credentials.json
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")

@app.route("/")
def index():
    return '<a href="/authorize">Connect your Gmail</a>'

@app.route("/authorize")
def authorize():
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token"
            }
        },
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    auth_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
    )
    session["state"] = state
    return redirect(auth_url)

@app.route("/oauth2callback")
def oauth2callback():
    state = session.get("state")
    if not state:
        return "Missing state parameter in session", 400

    try:
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                }
            },
            scopes=SCOPES,
            state=state,
            redirect_uri=REDIRECT_URI
        )

        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials

        os.makedirs("tokens", exist_ok=True)

        # Use Gmail API to get user's email
        user_service = build("oauth2", "v2", credentials=credentials)
        user_info = user_service.userinfo().get().execute()
        email = user_info.get("email", "unknown_user").replace("@", "_at_")

        # Save token using email
        with open(f"tokens/{email}.json", "w") as f:
            f.write(credentials.to_json())

        return f"Gmail connected successfully for {email}! You can now close this window."

    except Exception as e:
        return f"OAuth2 callback failed: {e}", 500

@app.route("/send_test_email")
def send_test_email():
    token_files = os.listdir("tokens")
    if not token_files:
        return "No users connected yet."

    try:
        # Load first token for test
        with open(f"tokens/{token_files[0]}", "r") as f:
            creds_data = json.load(f)

        creds = Credentials.from_authorized_user_info(creds_data, SCOPES)
        service = build("gmail", "v1", credentials=creds)

        # Create simple base64 message
        message = {
            "raw": base64.urlsafe_b64encode(
                b"From: me\nTo: me\nSubject: Test Email\n\nHello world!"
            ).decode("utf-8")
        }

        send = service.users().messages().send(userId="me", body=message).execute()
        return f"Email sent! ID: {send['id']}"
    except Exception as e:
        return f"Failed to send email: {e}"

if __name__ == "__main__":
    os.makedirs("tokens", exist_ok=True)
    app.run(host="0.0.0.0", port=5000)
