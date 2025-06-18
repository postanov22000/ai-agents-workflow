import os
import logging
import zipfile
from flask import Blueprint, request, jsonify
from supabase import create_client
from docxtpl import DocxTemplate
import pytesseract
from pdf2image import convert_from_path

# Initialize logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Supabase client setup
def get_supabase_client():
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY")
    if not url or not key:
        raise RuntimeError("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set")
    return create_client(url, key)

supabase = get_supabase_client()

# Blueprint for Transaction Autopilot
bp = Blueprint("transaction_autopilot", __name__)

@bp.route("/trigger", methods=["POST"])
def trigger_autopilot():
    payload = request.json or {}
    transaction_type = payload.get("transaction_type", "generic")
    data = payload.get("data", {})

    # 1. Generate LOI/PSA
    docs = []
    try:
        docs.append(generate_document("loi_template.docx", data, "LOI"))
        docs.append(generate_document("psa_template.docx", data, "PSA"))
    except Exception as e:
        logger.error(f"Document assembly failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

    # 2. Run error-hunting via keyword scanning
    errors = error_hunting(docs)
    if errors:
        logger.warning(f"Errors detected: {errors}")

    # 3. Bundle closing kit
    try:
        kit_zip = bundle_closing_kit(transaction_type, docs)
    except Exception as e:
        logger.error(f"Bundling failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

    # 4. Upload to Supabase Storage
    uploaded = []
    for file_path in kit_zip:
        key_name = os.path.basename(file_path)
        with open(file_path, "rb") as f:
            res = supabase.storage.from_("closing_kits").upload(key_name, f)
            uploaded.append(res.get("Key"))

    return jsonify({"status": "success", "files": uploaded})


def generate_document(template_name: str, context: dict, prefix: str) -> str:
    """
    Renders a .docx template with DocxTemplate and returns the output path.
    """
    template_path = os.path.join("templates/transaction_autopilot", template_name)
    tpl = DocxTemplate(template_path)
    tpl.render(context)
    output_path = os.path.join("/tmp", f"{prefix}_{context.get('id', '0')}.docx")
    tpl.save(output_path)
    logger.info(f"Generated document at {output_path}")
    return output_path


def error_hunting(doc_paths: list) -> dict:
    """
    Uses OCR to scan docs for missing required keywords.
    Returns a dict mapping file paths to lists of missing keywords.
    """
    results = {}
    for path in doc_paths:
        pages = convert_from_path(path)
        text = "".join(pytesseract.image_to_string(page) for page in pages).lower()
        missing = []
        for keyword in ["signature", "date", "buyer", "seller"]:
            if keyword not in text:
                missing.append(keyword)
        if missing:
            results[path] = missing
    return results


def bundle_closing_kit(transaction_type: str, docs: list) -> list:
    """
    Bundles generated docs into a zip archive and returns list with zip path.
    """
    kit_dir = os.path.join("/tmp", f"kit_{transaction_type}")
    os.makedirs(kit_dir, exist_ok=True)
    for doc in docs:
        os.replace(doc, os.path.join(kit_dir, os.path.basename(doc)))

    zip_path = os.path.join("/tmp", f"{transaction_type}_closing_kit.zip")
    with zipfile.ZipFile(zip_path, "w") as zf:
        for fname in os.listdir(kit_dir):
            zf.write(os.path.join(kit_dir, fname), arcname=fname)
    logger.info(f"Closing kit created at {zip_path}")
    return [zip_path]
