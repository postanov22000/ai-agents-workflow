import os
import json
from flask import Flask, redirect, request
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from supabase import create_client
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# Supabase setup
supabase = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_SERVICE_ROLE_KEY"])

# OAuth config
SCOPES = [
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/userinfo.email",
    "openid"
]
REDIRECT_URI = "https://replyzeai.onrender.com/oauth2callback"

# Create client_secrets.json from environment variable
CLIENT_SECRETS_JSON = os.getenv("CLIENT_SECRETS_JSON")
if CLIENT_SECRETS_JSON:
    with open("client_secrets.json", "w") as f:
        f.write(CLIENT_SECRETS_JSON)

@app.route("/")
def index():
    flow = Flow.from_client_secrets_file(
        "client_secrets.json",
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
    )
    auth_url, _ = flow.authorization_url(
        prompt="consent", access_type="offline", include_granted_scopes="true"
    )
    return redirect(auth_url)

@app.route("/oauth2callback")
def oauth2callback():
    flow = Flow.from_client_secrets_file(
        "client_secrets.json",
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
    )
    flow.fetch_token(authorization_response=request.url)

    credentials = flow.credentials
    service = build("gmail", "v1", credentials=credentials)
    profile = service.users().getProfile(userId="me").execute()
    user_email = profile["emailAddress"]

    # Save token to Supabase
    supabase.table('gmail_tokens').upsert({
        'user_email': user_email,
        'credentials': {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }
    }).execute()

    return f"Gmail connected successfully for {user_email}!"

@app.route("/process", methods=["GET"])
def process_emails():
    auth_token = request.args.get("token")
    if auth_token != os.environ.get("PROCESS_SECRET_TOKEN"):
        return "Unauthorized", 401
        
    try:
        from main import run_worker
        result = run_worker()
        return f"Processed: {result}"
    except Exception as e:
        import traceback
        traceback_str = traceback.format_exc()
        print("ERROR during processing:\n", traceback_str)
        return f"<pre>{traceback_str}</pre>", 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
