python -c "
from google_auth_oauthlib.flow import InstalledAppFlow
flow = InstalledAppFlow.from_client_secrets_file(
    'credentials.json',
    scopes=['https://www.googleapis.com/auth/gmail.modify']
)
creds = flow.run_local_server(port=0)
with open('token.json', 'w') as token:
    token.write(creds.to_json())
"
