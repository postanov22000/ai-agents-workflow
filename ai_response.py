from google_auth_oauthlib.flow import InstalledAppFlow

SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

flow = InstalledAppFlow.from_client_secrets_file(
    'credentials.json',
    scopes=SCOPES
)
creds = flow.run_local_server(port=0)

# Save token to file (optional)
with open('token.json', 'w') as token_file:
    token_file.write(creds.to_json())

# Print token JSON string (to copy into GitHub secrets)
print(creds.to_json())
