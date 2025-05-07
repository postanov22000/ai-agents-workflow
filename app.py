import os
import json
import hashlib
import logging
from flask import Flask, redirect, request, session, jsonify
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from supabase import create_client
from werkzeug.exceptions import HTTPException
from datetime import datetime, timezone

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24))

# Configuration
SCOPES = [
    "https://www.googleapis.com/auth/userinfo.email",
    "openid",
    "https://www.googleapis.com/auth/gmail.send"
]
CLIENT_SECRETS_FILE = "client_secrets.json"
REDIRECT_URI = "https://replyzeai.onrender.com/oauth2callback"
DAILY_EMAIL_LIMIT = 95  # Stay under Google's 100/day limit

# Initialize Supabase
try:
    supabase = create_client(
        os.environ["SUPABASE_URL"],
        os.environ["SUPABASE_SERVICE_ROLE_KEY"]
    )
    logger.info("Supabase client initialized successfully")
except KeyError as e:
    logger.error(f"Missing environment variable: {str(e)}")
    raise
except Exception as e:
    logger.error(f"Supabase initialization failed: {str(e)}")
    raise

def validate_client_secrets():
    """Ensure client_secrets.json exists"""
    if not os.path.exists(CLIENT_SECRETS_FILE):
        client_secrets = os.environ.get("GOOGLE_CLIENT_SECRETS")
        if client_secrets:
            try:
                with open(CLIENT_SECRETS_FILE, "w") as f:
                    f.write(client_secrets)
                logger.info("Created client_secrets.json from env")
            except Exception as e:
                logger.error(f"Failed to write client_secrets.json: {str(e)}")
                raise
        else:
            logger.error("Missing both client_secrets.json and GOOGLE_CLIENT_SECRETS env")
            raise RuntimeError("Missing OAuth configuration")

validate_client_secrets()

@app.errorhandler(Exception)
def handle_exception(e):
    logger.exception("An error occurred")
    return jsonify(error="Internal Server Error"), 500

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
            prompt="consent",
            include_granted_scopes="false"
        )
        session["state"] = state
        return redirect(auth_url)
    except Exception as e:
        logger.error(f"Authorization initialization failed: {str(e)}")
        return jsonify(error="Authorization failed"), 500

@app.route("/oauth2callback")
def oauth2callback():
    try:
        if "state" not in session:
            logger.error("Missing session state in callback")
            return jsonify(error="Invalid session"), 400

        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            state=session["state"],
            redirect_uri=REDIRECT_URI
        )

        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials

        user_info_service = build("oauth2", "v2", credentials=credentials)
        user_info = user_info_service.userinfo().get().execute()
        user_email = user_info.get("email")

        if not user_email:
            logger.error("Failed to retrieve user email from Google")
            return jsonify(error="Email not found"), 400

        credentials_data = {
            "token": credentials.token,
            "refresh_token": credentials.refresh_token,
            "token_uri": credentials.token_uri,
            "client_id": credentials.client_id,
            "client_secret": credentials.client_secret,
            "scopes": credentials.scopes
        }

        upsert_response = supabase.table("gmail_tokens").upsert({
            "user_email": user_email,
            "credentials": credentials_data
        }).execute()

        if not upsert_response.data:
            logger.error("Supabase upsert failed")
            return jsonify(error="Credential storage failed"), 500

        logger.info(f"Stored credentials for {user_email}")
        return f"✅ Gmail connected for {user_email}"

    except Exception as e:
        logger.error(f"OAuth callback failed: {str(e)}")
        return jsonify(error="Connection failed"), 500

@app.route("/process", methods=["GET"])
def process_emails():
    try:
        auth_token = request.args.get("token")
        if not auth_token or auth_token != os.environ.get("PROCESS_SECRET_TOKEN"):
            logger.warning("Invalid process token attempt")
            return jsonify(error="Unauthorized"), 401

        # Check daily email limit
        sent_today = supabase.table("emails") \
                          .select("id", count=True) \
                          .gte("sent_at", datetime.now(timezone.utc).isoformat()) \
                          .execute().count
        
        if sent_today >= DAILY_EMAIL_LIMIT:
            logger.warning(f"Daily limit reached: {sent_today}/{DAILY_EMAIL_LIMIT}")
            return jsonify(
                status="limit_reached",
                sent_today=sent_today,
                limit=DAILY_EMAIL_LIMIT
            ), 429

        from main import run_worker
        result = run_worker()
        return jsonify(status="success", result=result)

    except Exception as e:
        logger.error(f"Processing failed: {str(e)}")
        return jsonify(error=str(e)), 500

@app.route("/health")
def health_check():
    try:
        email_count = supabase.table("emails").select("id", count=True).execute().count
        token_count = supabase.table("gmail_tokens").select("user_email").execute().count
        return jsonify(
            database_connected=True,
            emails=email_count,
            gmail_connections=token_count
        )
    except Exception as e:
        return jsonify(
            database_connected=False,
            error=str(e)
        ), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
