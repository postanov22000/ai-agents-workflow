import os
import logging
import zipfile
from flask import Blueprint, request, jsonify
from supabase import create_client
from docxtpl import DocxTemplate
import docx2txt
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

    # 0) Ensure we have a transaction ID to update
    tx_id = payload.get("data", {}).get("id")
    if not tx_id:
        return jsonify({"status": "error", "message": "Missing transaction ID"}), 400

    ttype = payload.get("transaction_type", "generic")
    data  = payload.get("data", {})

    # 1) Generate LOI & PSA
    try:
        loi_path = generate_document("loi_template.docx", data, "LOI")
        psa_path = generate_document("psa_template.docx", data, "PSA")
        docs = [loi_path, psa_path]
    except Exception as e:
        logger.error(f"Document assembly failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

    # 2) Error‑hunting scan
    errors = error_hunting(docs)
    if errors:
        logger.warning(f"Errors detected: {errors}")

    # 3) Bundle into ZIP
    try:
        kit_zip_list = bundle_closing_kit(ttype, docs)
    except Exception as e:
        logger.error(f"Bundling failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

    # 4) Upload to Supabase Storage, then write kit_url back to transactions table
    uploaded_files = []
    for zip_path in kit_zip_list:
        filename   = os.path.basename(zip_path)
        public_url = (
            f"{os.environ['SUPABASE_URL']}"
            f"/storage/v1/object/closing-kits/{filename}"
        )

        # attempt upload (may already exist)
        with open(zip_path, "rb") as f:
            try:
                supabase.storage.from_("closing-kits").upload(filename, f)
            except Exception as e:
                logger.warning(f"Upload failed for {filename}: {e}, reusing existing object")

        # persist the public URL back into the transaction
        try:
            supabase.table("transactions") \
                     .update({"kit_url": public_url}) \
                     .eq("id", tx_id) \
                     .execute()
        except Exception as e:
            logger.error(f"Failed to update transaction {tx_id} with kit_url: {e}")

        uploaded_files.append(filename)

    return jsonify({"status": "success", "files": uploaded_files}), 200


def generate_document(template_name: str, context: dict, prefix: str) -> str:
    tpl_path = os.path.join("templates/transaction_autopilot", template_name)
    tpl = DocxTemplate(tpl_path)
    tpl.render(context)
    out_path = os.path.join("/tmp", f"{prefix}_{context.get('id','0')}.docx")
    tpl.save(out_path)
    logger.info(f"Generated document at {out_path}")
    return out_path


def error_hunting(paths: list) -> dict:
    results = {}
    for path in paths:
        text = ""
        if path.lower().endswith(".docx"):
            text = docx2txt.process(path)
        elif path.lower().endswith(".pdf"):
            try:
                pages = convert_from_path(path)
                text = "".join(pytesseract.image_to_string(pg) for pg in pages)
            except Exception as e:
                logger.error(f"PDF OCR failed for {path}: {e}")
                continue
        else:
            logger.warning(f"Skipping unknown format: {path}")
            continue

        missing = []
        lower_text = text.lower()
        for keyword in ["signature", "date", "buyer", "seller"]:
            if keyword not in lower_text:
                missing.append(keyword)
        if missing:
            results[path] = missing
    return results


def bundle_closing_kit(ttype: str, docs: list) -> list:
    kit_dir = os.path.join("/tmp", f"kit_{ttype}")
    os.makedirs(kit_dir, exist_ok=True)
    for doc_path in docs:
        os.replace(doc_path, os.path.join(kit_dir, os.path.basename(doc_path)))

    zip_path = os.path.join("/tmp", f"{ttype}_closing_kit.zip")
    with zipfile.ZipFile(zip_path, "w") as zf:
        for fname in os.listdir(kit_dir):
            full_path = os.path.join(kit_dir, fname)
            zf.write(full_path, arcname=fname)

    logger.info(f"Closing kit created at {zip_path}")
    return [zip_path]
