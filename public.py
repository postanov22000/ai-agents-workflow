# public.py

import os
import zipfile
import tempfile
import uuid
from io import BytesIO

from flask import Blueprint, request, send_file, jsonify, render_template, abort
from flask_cors import CORS
from docxtpl import DocxTemplate

public_bp = Blueprint("public", __name__)
# Allow CORS for demo endpoints
CORS(public_bp, resources={r"/api/*": {"origins": "*"}})

@public_bp.route("/api/generate-reply-prompt", methods=["OPTIONS", "POST"])
def generate_reply_prompt():
    if request.method == "OPTIONS":
        return ("", 204)

    data = request.get_json(force=True)
    prompt = data.get("prompt", "").strip()
    if not prompt:
        return jsonify({"error": "Missing prompt"}), 400

    try:
        from utils import callAIML_from_flask
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
    bio = BytesIO()
    tpl.save(bio)
    bio.seek(0)
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
    bio = BytesIO()
    tpl.save(bio)
    bio.seek(0)
    return send_file(
        bio,
        as_attachment=True,
        download_name=f"PSA_{payload.get('id','doc')}.docx",
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )

@public_bp.route("/api/demo/closing-kit", methods=["POST"])
def demo_closing_kit():
    """
    Demo endpoint that accepts JSON payload:
      { id, buyer_name, seller_name, property_address, offer_price, special_terms? }
    Renders LOI + PSA, bundles into ZIP, returns it.
    """
    data = request.get_json(force=True)
    required = ["id", "buyer_name", "seller_name", "property_address", "purchase_price"]
    if any(not data.get(f) for f in required):
        return jsonify({"error": "Missing id/buyer_name/seller_name/property_address/purchase_price"}), 400

    # Render templates to temp files
    tmpdir = tempfile.mkdtemp()
    parts = []
    for tpl_fname, prefix in [
        ("loi_template.docx", "LOI"),
        ("psa_template.docx", "PSA")
    ]:
        tpl = DocxTemplate(f"templates/transaction_autopilot/{tpl_fname}")
        tpl.render(data)
        out_name = f"{prefix}_{data['id']}_{uuid.uuid4().hex[:6]}.docx"
        out_path = os.path.join(tmpdir, out_name)
        tpl.save(out_path)
        parts.append(out_path)

    # Bundle into an in-memory ZIP
    zip_io = BytesIO()
    with zipfile.ZipFile(zip_io, "w") as zf:
        for p in parts:
            zf.write(p, arcname=os.path.basename(p))
    zip_io.seek(0)

    return send_file(
        zip_io,
        as_attachment=True,
        download_name=f"demo_closing_kit_{data['id']}.zip",
        mimetype="application/zip"
    )
@public_bp.route("/demo")
def demo():
    demo_data = {
        "closing_Date": "2025-07-15",
        "purchase_Price": 350000
    }
    return render_template("demo.html", **demo_data)

@public_bp.route("/<path:page>")
def catch_all(page):
    if page == "signin":
        # let the main app handle this
        abort(404)
    return render_template(f"{page}.html")
