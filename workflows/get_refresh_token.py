from google_auth_oauthlib.flow import InstalledAppFlow

# Paste your client ID and secret from Google Cloud
CLIENT_CONFIG = {
    "web": {
        "client_id": "YOUR_CLIENT_ID",
        "client_secret": "YOUR_CLIENT_SECRET",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token"
    }
}

SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

flow = InstalledAppFlow.from_client_config(CLIENT_CONFIG, SCOPES)
creds = flow.run_local_server(port=0)  # Opens browser for login

print("Refresh token:", creds.refresh_token)  # This is what you need!
