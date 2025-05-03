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

# Set redirect URI to match Google Cloud Console
REDIRECT_URI = "https://replyzeai.onrender.com/oauth2callback"

SCOPES = ["https://www.googleapis.com/auth/gmail.send"]

@app.route("/")
def index():
    return '<a href="/authorize">Connect your Gmail</a>'

@app.route("/authorize")
def authorize():
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": os.environ["GOOGLE_CLIENT_ID"],
                "client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        },
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
    )
    auth_url, state = flow.authorization_url(access_type="offline", include_granted_scopes="true")
    session["state"] = state
    return redirect(auth_url)

@app.route("/oauth2callback")
def oauth2callback():
    state = session.get("state")
    if not state:
        return "Missing state parameter in session", 400

    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": os.environ["GOOGLE_CLIENT_ID"],
                "client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        },
        scopes=SCOPES,
        state=state,
        redirect_uri=REDIRECT_URI,
    )
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials

    os.makedirs("tokens", exist_ok=True)
    filename = f"tokens/{credentials.id_token}.json"
    with open(filename, "w") as f:
        f.write(credentials.to_json())

    return "Gmail connected successfully! You can now close this window."

@app.route("/send_test_email")
def send_test_email():
    token_files = os.listdir("tokens")
    if not token_files:
        return "No users connected yet."

    with open(f"tokens/{token_files[0]}", "r") as f:
        creds_data = json.load(f)

    creds = Credentials.from_authorized_user_info(creds_data, SCOPES)
    service = build("gmail", "v1", credentials=creds)

    # Base64 encode "Hello world" email
    raw = {
        "raw": "SGVsbG8gd29ybGQ="  # base64 for "Hello world"
    }

    try:
        result = service.users().messages().send(userId="me", body=raw).execute()
        return f"Email sent! ID: {result['id']}"
    except Exception as e:
        return f"Failed to send email: {e}"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
