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
    ttype = payload.get("transaction_type", "generic")
    data = payload.get("data", {})

    # 1) Generate LOI and PSA
    docs = []
    try:
        docs.append(generate_document("loi_template.docx", data, "LOI"))
        docs.append(generate_document("psa_template.docx", data, "PSA"))
    except Exception as e:
        logger.error(f"Document assembly failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

    # 2) Error-hunting scan
    errors = error_hunting(docs)
    if errors:
        logger.warning(f"Errors detected: {errors}")

    # 3) Bundle into ZIP
    try:
        kit_zip = bundle_closing_kit(ttype, docs)
    except Exception as e:
        logger.error(f"Bundling failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

    # 4) Upload to Supabase Storage
    uploaded = []
    for path in kit_zip:
        name = os.path.basename(path)
        with open(path, "rb") as f:
            try:
                res = supabase.storage.from_("closing-kits").upload(name, f)
                # Parse response dict
                if isinstance(res, dict):
                    key = res.get("Key") or res.get("key") or name
                else:
                    key = name
            except Exception as e:
                logger.warning(f"Upload failed for {name}: {e}, reusing existing file")
                key = name
            uploaded.append(key)

    return jsonify({"status": "success", "files": uploaded}), 200


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
    for p in paths:
        if p.lower().endswith(".docx"):
            text = docx2txt.process(p)
        elif p.lower().endswith(".pdf"):
            try:
                pages = convert_from_path(p)
                text = "".join(pytesseract.image_to_string(pg) for pg in pages)
            except Exception as e:
                logger.error(f"PDF OCR failed for {p}: {e}")
                continue
        else:
            logger.warning(f"Skipping unknown format for error hunting: {p}")
            continue

        missing = []
        low = text.lower()
        for kw in ["signature", "date", "buyer", "seller"]:
            if kw not in low:
                missing.append(kw)
        if missing:
            results[p] = missing
    return results


def bundle_closing_kit(ttype: str, docs: list) -> list:
    kit_dir = os.path.join("/tmp", f"kit_{ttype}")
    os.makedirs(kit_dir, exist_ok=True)
    for doc in docs:
        os.replace(doc, os.path.join(kit_dir, os.path.basename(doc)))

    zip_path = os.path.join("/tmp", f"{ttype}_closing_kit.zip")
    with zipfile.ZipFile(zip_path, "w") as zf:
        for fname in os.listdir(kit_dir):
            zf.write(os.path.join(kit_dir, fname), arcname=fname)
    logger.info(f"Closing kit created at {zip_path}")
    return [zip_path]
