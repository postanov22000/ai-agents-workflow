import os
import requests
import pickle
import hashlib
import base64
from datetime import datetime
from email.mime.text import MIMEText
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from supabase import create_client

# Supabase setup
SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
HF_API_KEY = os.environ["HF_API_KEY"]
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

def load_credentials(sender_email):
    token_path = os.path.join("tokens", hashlib.sha256(sender_email.encode()).hexdigest() + ".pickle")
    if not os.path.exists(token_path):
        raise Exception(f"No Gmail credentials found for {sender_email}")
    with open(token_path, "rb") as token_file:
        creds = pickle.load(token_file)
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
        with open(token_path, "wb") as token_file:
            pickle.dump(creds, token_file)
    return creds

def create_message(to, subject, body):
    message = MIMEText(body)
    message["to"] = to
    message["subject"] = subject
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    return {"raw": raw}

def run_worker():
    # Step 1: generate responses for emails in "preprocessing"
    preprocessing = supabase.table("emails").select("*").eq("status", "preprocessing").execute().data
    for email in preprocessing:
        id = email["id"]
        try:
            supabase.table("emails").update({"status": "processing"}).eq("id", id).execute()
            prompt = f"you are a mid lvl estate agent, respond to this email:\n\n{email['original_content']}"
            response = requests.post(
                "https://api-inference.huggingface.co/models/mistralai/Mixtral-8x7B-Instruct-v0.1",
                headers={
                    "Authorization": f"Bearer {HF_API_KEY}",
                    "Content-Type": "application/json"
                },
                json={"inputs": prompt, "options": {"use_cache": False}}
            )
            reply = response.json()[0]["generated_text"].strip()
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

    # Step 2: send emails in "ready_to_send"
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

    return "Done"
