import os
from flask import Flask, render_template, request, redirect, jsonify
from datetime import date
from supabase import create_client, Client

app = Flask(__name__, template_folder="templates")
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret")

# Connect to Supabase 1
SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_ANON_KEY = os.environ["SUPABASE_ANON_KEY"]
supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

DAILY_LIMIT = 20

@app.route("/")
def home():
    return redirect("/dashboard")

@app.route("/dashboard")
def dashboard():
    user_id = request.args.get("user_id")
    if not user_id:
        return "Missing user_id", 401

    today = date.today().isoformat()
    sent = supabase.table("emails").select("sent_at").eq("user_id", user_id).eq("status", "sent").execute().data
    count = len([e for e in sent if e["sent_at"] and e["sent_at"].startswith(today)])
    time_saved = count * 3

    profile = supabase.table("profiles").select("full_name, ai_enabled").eq("id", user_id).single().execute().data
    print("Rendering dashboard for", profile["full_name"], count, "emails")
    return render_template("dashboard.html",
        name=profile["full_name"],
        user_id=user_id,
        emails_sent=count,
        time_saved=time_saved,
        ai_enabled=profile.get("ai_enabled", True)
    )

@app.route("/disconnect_gmail", methods=["POST"])
def disconnect_gmail():
    user_id = request.form.get("user_id")
    supabase.table("gmail_tokens").delete().eq("user_id", user_id).execute()
    return redirect(f"/dashboard?user_id={user_id}")

@app.route("/admin")
def admin():
    return render_template("admin.html")

@app.route("/api/admin/users")
def api_admin_users():
    users = supabase.table("profiles").select("*").execute().data
    today = date.today().isoformat()

    results = []
    for user in users:
        sent = supabase.table("emails").select("sent_at").eq("user_id", user["id"]).eq("status", "sent").execute().data
        count = len([e for e in sent if e["sent_at"] and e["sent_at"].startswith(today)])
        results.append({
            "id": user["id"],
            "name": user["full_name"],
            "enabled": user.get("ai_enabled", True),
            "emails_today": count
        })

    return jsonify(results)

@app.route("/api/admin/toggle_status", methods=["POST"])
def api_toggle_status():
    user_id = request.json.get("user_id")
    enable = request.json.get("enable", True)
    supabase.table("profiles").update({"ai_enabled": enable}).eq("id", user_id).execute()
    return jsonify({"success": True})

if __name__ == "__main__":
    app.run(debug=True)
