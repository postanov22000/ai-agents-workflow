import os
import json
from flask import Flask, redirect, request, session, url_for
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "supersecretkey")

SCOPES = ["https://www.googleapis.com/auth/gmail.send"]
CLIENT_SECRETS_FILE = "credentials.json"

# Ensure tokens directory exists
os.makedirs("tokens", exist_ok=True)

@app.route("/")
def index():
    return '<h1>ReplyzeAI</h1><a href="/authorize">Connect your Gmail</a>'

@app.route("/authorize")
def authorize():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=url_for("oauth2callback", _external=True)
    )
    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="false",
        prompt="consent"
    )
    session["state"] = state
    return redirect(auth_url)

@app.route("/oauth2callback")
def oauth2callback():
    state = session.get("state")
    if not state:
        return "Missing state in session.", 400

    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=state,
        redirect_uri=url_for("oauth2callback", _external=True)
    )

    try:
        flow.fetch_token(authorization_response=request.url)
    except Exception as e:
        return f"OAuth2 callback failed: {e}", 400

    credentials = flow.credentials

    user_id = credentials.id_token.get("sub")  # unique Google user ID
    token_path = f"tokens/{user_id}.json"

    with open(token_path, "w") as token_file:
        token_file.write(credentials.to_json())

    return "✅ Gmail connected successfully! You can close this tab."

@app.route("/send_test_email")
def send_test_email():
    token_files = os.listdir("tokens")
    if not token_files:
        return "❌ No users connected yet."

    # Just test with the first available user's token
    token_path = f"tokens/{token_files[0]}"
    with open(token_path, "r") as f:
        creds_data = json.load(f)

    creds = Credentials.from_authorized_user_info(creds_data, SCOPES)
    service = build("gmail", "v1", credentials=creds)

    # A simple test message (base64 of "Hello world" email)
    message = {
        "raw": "RnJvbTogbWUKeW91QGV4YW1wbGUuY29tClN1YmplY3Q6IFRlc3QKClRoaXMgaXMgYSB0ZXN0IGVtYWlsLg=="
    }

    try:
        send = service.users().messages().send(userId="me", body=message).execute()
        return f"✅ Email sent! ID: {send['id']}"
    except Exception as e:
        return f"❌ Failed to send email: {e}"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
