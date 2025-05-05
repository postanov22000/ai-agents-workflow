import os
import requests
from datetime import datetime
from email.mime.text import MIMEText
import base64
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from supabase import create_client

# Supabase setup
supabase = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_SERVICE_ROLE_KEY"])

def load_credentials(sender_email):
    response = supabase.table('gmail_tokens').select('credentials').eq('user_email', sender_email).execute()
    if not response.data:
        raise Exception(f"No Gmail credentials found for {sender_email}")
    
    creds_data = response.data[0]['credentials']
    creds = Credentials(
        token=creds_data['token'],
        refresh_token=creds_data['refresh_token'],
        token_uri=creds_data['token_uri'],
        client_id=creds_data['client_id'],
        client_secret=creds_data['client_secret'],
        scopes=creds_data['scopes']
    )
    
    if creds.expired:
        creds.refresh(Request())
        # Update Supabase with new token
        supabase.table('gmail_tokens').upsert({
            'user_email': sender_email,
            'credentials': {
                'token': creds.token,
                'refresh_token': creds.refresh_token,
                'token_uri': creds.token_uri,
                'client_id': creds.client_id,
                'client_secret': creds.client_secret,
                'scopes': creds.scopes
            }
        }).execute()
    
    return creds

def create_message(to, subject, body):
    message = MIMEText(body)
    message["to"] = to
    message["subject"] = subject
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    return {"raw": raw}

def run_worker():
    # Process preprocessing emails
    preprocessing = supabase.table("emails").select("*").eq("status", "preprocessing").execute().data
    for email in preprocessing:
        id = email["id"]
        try:
            supabase.table("emails").update({"status": "processing"}).eq("id", id).execute()
            
            prompt = f"you are a mid lvl estate agent, respond to this email:\n\n{email['original_content']}"
            response = requests.post(
                "https://api-inference.huggingface.co/models/mistralai/Mixtral-8x7B-Instruct-v0.1",
                headers={"Authorization": f"Bearer {os.environ['HF_API_KEY']}"},
                json={"inputs": prompt, "options": {"use_cache": False}}
            )
            
            if response.status_code != 200:
                raise Exception(f"Hugging Face API Error: {response.text}")
            
            try:
                reply = response.json()[0]["generated_text"].strip()
            except (KeyError, IndexError) as e:
                raise Exception("Unexpected response format from API") from e
                
            supabase.table("emails").update({
                "processed_content": reply,
                "status": "ready_to_send",
                "processed_at": datetime.utcnow().isoformat()
            }).eq("id", id).execute()
            
        except Exception as e:
            supabase.table("emails").update({
                "status": "error",
                "error_message": str(e)
            }).eq("id", id).execute()

    # Send ready emails
    ready = supabase.table("emails").select("*").eq("status", "ready_to_send").execute().data
    for email in ready:
        id = email["id"]
        try:
            sender = email["sender_email"]
            recipient = email["recipient_email"]
            subject = email.get("subject") or "Re: Your inquiry"
            body = email["processed_content"]

            creds = load_credentials(sender)
            service = build("gmail", "v1", credentials=creds)
            msg = create_message(recipient, subject, body)
            service.users().messages().send(userId="me", body=msg).execute()

            supabase.table("emails").update({
                "status": "sent",
                "sent_at": datetime.utcnow().isoformat()
            }).eq("id", id).execute()
            
        except Exception as e:
            supabase.table("emails").update({
                "status": "failed",
                "error_message": str(e)
            }).eq("id", id).execute()

    return f"Processed {len(preprocessing)} emails, sent {len(ready)} emails"

if __name__ == "__main__":
    run_worker()
