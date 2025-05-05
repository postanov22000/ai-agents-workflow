import os
import json
import hashlib
import pickle
from flask import Flask, redirect, request
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

app = Flask(__name__)

# OAuth configuration
CLIENT_SECRETS_FILE = "client_secrets.json"
SCOPES = [
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/userinfo.email",
    "openid",
]
REDIRECT_URI = "https://replyzeai.onrender.com/oauth2callback"

@app.route("/")
def index():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
    )
    auth_url, _ = flow.authorization_url(
        prompt="consent",
        access_type="offline",
        include_granted_scopes="true"
    )
    return redirect(auth_url)

@app.route("/oauth2callback")
def oauth2callback():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
    )
    flow.fetch_token(authorization_response=request.url)

    credentials = flow.credentials
    service = build("gmail", "v1", credentials=credentials)
    profile = service.users().getProfile(userId="me").execute()
    user_email = profile["emailAddress"]

    # Save token
    os.makedirs("tokens", exist_ok=True)
    filename = os.path.join("tokens", hashlib.sha256(user_email.encode()).hexdigest() + ".pickle")
    with open(filename, "wb") as token:
        pickle.dump(credentials, token)

    return f"Gmail connected successfully for {user_email}!"

@app.route("/process", methods=["GET"])
def process_emails():
    try:
        # Dynamic import inside route to avoid circular errors
        import main
        result = main.run_worker()
        return f"Processed {result} emails."
    except Exception as e:
        # Print error to logs for debugging
        print(f"Error in /process: {e}")
        return f"Internal Server Error: {str(e)}", 500

if __name__ == "__main__":
    app.run(debug=True)
