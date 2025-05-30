import os
import json
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

@app.route("/")
def index():
    return '<a href="/authorize">Connect your Gmail</a>'

@app.route("/authorize")
def authorize():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=url_for("oauth2callback", _external=True)
    )
    auth_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
    session["state"] = state
    return redirect(auth_url)

@app.route("/oauth2callback")
def oauth2callback():
    state = session["state"]
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=state,
        redirect_uri=url_for("oauth2callback", _external=True)
    )
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials

    # Store the user's credentials in a simple JSON file (you can use DB in production)
    with open(f"tokens/{credentials.id_token}.json", "w") as f:
        f.write(credentials.to_json())

    return "Gmail connected successfully! You can now close this window."

@app.route("/send_test_email")
def send_test_email():
    # This uses the first saved token just for testing
    token_files = os.listdir("tokens")
    if not token_files:
        return "No users connected yet."

    with open(f"tokens/{token_files[0]}", "r") as f:
        creds_data = json.load(f)
    creds = Credentials.from_authorized_user_info(creds_data, SCOPES)

    service = build("gmail", "v1", credentials=creds)

    message = {
        "raw": "SGVsbG8gd29ybGQ="  # base64 of "Hello world"
    }

    try:
        send = service.users().messages().send(userId="me", body=message).execute()
        return f"Email sent! ID: {send['id']}"
    except Exception as e:
        return f"Failed to send email: {e}"

if __name__ == "__main__":
    os.makedirs("tokens", exist_ok=True)
    app.run(host="0.0.0.0", port=5000)
