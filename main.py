import os
import requests
from datetime import datetime
from supabase import create_client

def run_worker():
    supabase = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_SERVICE_ROLE_KEY"])
    hf_token = os.environ["HF_API_KEY"]

    emails = supabase.table("emails").select("*").eq("status", "preprocessing").execute().data
    results = []

    for email in emails:
        id = email["id"]
        try:
            supabase.table("emails").update({"status": "processing"}).eq("id", id).execute()

            prompt = f"you are a mid lvl estate agent, respond to this email:\n\n{email['original_content']}"
            response = requests.post(
                "https://api-inference.huggingface.co/models/mistralai/Mixtral-8x7B-Instruct-v0.1",
                headers={
                    "Authorization": f"Bearer {hf_token}",
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

            results.append(id)
        except Exception as e:
            print(f"Failed email {id}: {e}")
            supabase.table("emails").update({
                "status": "error",
                "error_message": str(e)
            }).eq("id", id).execute()

    return results
