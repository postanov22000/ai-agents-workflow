# app.py (Cloud Version with Supabase DB storage)
import os
import json
from flask import Flask, session, redirect, request
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from supabase import create_client
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-key")  # Use env var in production

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # Use HTTPS in production

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

SCOPES = ["https://www.googleapis.com/auth/gmail.send"]
REDIRECT_URI = os.getenv("REDIRECT_URI")  # e.g. https://your-app.onrender.com/oauth2callback

@app.route("/")
def index():
    return '<a href="/authorize">Connect your Gmail</a>'

@app.route("/authorize")
def authorize():
    flow = Flow.from_client_secrets_file(
        "credentials.json",
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    auth_url, state = flow.authorization_url(access_type="offline", include_granted_scopes="true")
    session["state"] = state
    return redirect(auth_url)

@app.route("/oauth2callback")
def oauth2callback():
    state = session["state"]
    flow = Flow.from_client_secrets_file(
        "credentials.json",
        scopes=SCOPES,
        state=state,
        redirect_uri=REDIRECT_URI
    )
    flow.fetch_token(authorization_response=request.url)

    credentials = flow.credentials
    service = build("oauth2", "v2", credentials=credentials)
    user_info = service.userinfo().get().execute()
    user_email = user_info["email"]

    # Store in Supabase
    supabase.table("gmail_tokens").upsert({
        "user_email": user_email,
        "credentials": json.loads(credentials.to_json())
    }).execute()

    return f"Gmail connected for {user_email}."

if __name__ == "__main__":
    app.run()
