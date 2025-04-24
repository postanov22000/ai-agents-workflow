from google_auth_oauthlib.flow import InstalledAppFlow

# Paste your client ID and secret from Google Cloud
CLIENT_CONFIG = {
    "web": {
        "client_id": "953541304655-4sh937o76s1lefsik39p824d4dgqqe3p.apps.googleusercontent.com",
        "client_secret": "{"web":{"client_id":"953541304655-4sh937o76s1lefsik39p824d4dgqqe3p.apps.googleusercontent.com","project_id":"innate-agency-457817-d8","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs","client_secret":"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"}}",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token"
    }
}

SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

flow = InstalledAppFlow.from_client_config(CLIENT_CONFIG, SCOPES)
creds = flow.run_local_server(port=0)  # Opens browser for login

print("Refresh token:", creds.refresh_token)  # This is what you need!
