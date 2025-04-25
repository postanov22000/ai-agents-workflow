import os
import supabase
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request

# Initialize Supabase client
url = os.getenv('SUPABASE_URL')
key = os.getenv('SUPABASE_KEY')
supabase_client = supabase.create_client(url, key)

SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

def get_credentials():
    """Get valid credentials with automatic refresh handling"""
    creds = None

    # Fetch token data from Supabase
    response = supabase_client.table('tokens').select('token_json').eq('email', 'your-email@example.com').single().execute()
    token_data = response['data']['token_json']

    if token_data:
        creds = Credentials.from_authorized_user_info(token_data, SCOPES)

    # Handle token refreshing if expired
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
        # Save refreshed token to Supabase
        supabase_client.table('tokens').update({"token_json": creds.to_json()}).eq('email', 'socilorbit.official.amanda@gmail.com').execute()

    return creds
