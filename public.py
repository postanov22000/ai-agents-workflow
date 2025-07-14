# public.py
from flask import Blueprint, request, jsonify, send_file
from flask_cors import CORS
from io import BytesIO
from docxtpl import DocxTemplate
from utils import callAIML_from_flask  # your utility function
# (you may need to adjust imports depending on your package layout)

public_bp = Blueprint("public", __name__)
# Apply CORS just to this blueprint
CORS(public_bp, resources={r"/api/*": {"origins": "https://replyzeai.vercel.app"}})

@public_bp.route("/api/generate-reply-prompt", methods=["OPTIONS", "POST"])
def generate_reply_prompt():
    if request.method == "OPTIONS":
        return ("", 204)  # CORS preflight handled by flask‑CORS

    data = request.get_json(force=True)
    prompt = data.get("prompt", "").strip()
    if not prompt:
        return jsonify({"error": "Missing prompt"}), 400

    try:
        reply = callAIML_from_flask(prompt)
        return jsonify({"reply": reply})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@public_bp.route("/api/generate-loi", methods=["OPTIONS", "POST"])
def generate_loi():
    if request.method == "OPTIONS":
        return ("", 204)

    payload = request.get_json(force=True)
    tpl = DocxTemplate("templates/transaction_autopilot/loi_template.docx")
    tpl.render(payload)
    bio = BytesIO(); tpl.save(bio); bio.seek(0)
    return send_file(
        bio,
        as_attachment=True,
        download_name=f"LOI_{payload.get('id','doc')}.docx",
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )

@public_bp.route("/api/generate-psa", methods=["OPTIONS", "POST"])
def generate_psa():
    if request.method == "OPTIONS":
        return ("", 204)

    payload = request.get_json(force=True)
    tpl = DocxTemplate("templates/transaction_autopilot/psa_template.docx")
    tpl.render(payload)
    bio = BytesIO(); tpl.save(bio); bio.seek(0)
    return send_file(
        bio,
        as_attachment=True,
        download_name=f"PSA_{payload.get('id','doc')}.docx",
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )
