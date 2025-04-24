python -c "
from google_auth_oauthlib.flow import InstalledAppFlow
flow = InstalledAppFlow.from_client_secrets_file(
    'credentials.json',
    scopes=['https://www.googleapis.com/auth/gmail.modify']
)
creds = flow.run_local_server(port=0)
print('=== COPY BELOW THIS LINE ===')
print(creds.to_json())
print('=== END OF TOKEN ===')
"
