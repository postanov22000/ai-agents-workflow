import os
import logging
import zipfile
from flask import Blueprint, request, jsonify
from supabase import create_client
from docxtpl import DocxTemplate
import pytesseract
from pdf2image import convert_from_path
import docx2txt

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

    docs = []
    try:
        docs.append(generate_document("loi_template.docx", data, "LOI"))
        docs.append(generate_document("psa_template.docx", data, "PSA"))
    except Exception as e:
        logger.error(f"Document assembly failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

    errors = error_hunting(docs)
    if errors:
        logger.warning(f"Errors detected: {errors}")

    try:
        kit_zip = bundle_closing_kit(ttype, docs)
    except Exception as e:
        logger.error(f"Bundling failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

    uploaded = []
    for path in kit_zip:
        name = os.path.basename(path)
        with open(path, "rb") as f:
            res = supabase.storage.from_("closing-kits").upload(name, f)
            # extract Key from response
            key = None
            try:
                # supabase-py may return a dict
                if isinstance(res, dict):
                    key = res.get("Key") or res.get("key")
                else:
                    data = res.json()
                    key = data.get("Key") or data.get("key")
            except Exception as e:
                logger.error(f"Failed to parse upload response for {name}: {e}")
            if not key:
                # fallback: use storage URL path
                key = name
            uploaded.append(key)

    return jsonify({"status": "success", "files": uploaded}), 200({"status": "success", "files": uploaded}), 200


def generate_document(template_name: str, context: dict, prefix: str) -> str:
    tpl_path = os.path.join("templates/transaction_autopilot", template_name)
    tpl = DocxTemplate(tpl_path)
    tpl.render(context)
    out = os.path.join("/tmp", f"{prefix}_{context.get('id','0')}.docx")
    tpl.save(out)
    logger.info(f"Generated document at {out}")
    return out


def error_hunting(paths: list) -> dict:
    results = {}
    for p in paths:
        text = ""
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
        found = []
        low = text.lower()
        for kw in ["signature", "date", "buyer", "seller"]:
            if kw not in low:
                found.append(kw)
        if found:
            results[p] = found
    return results


def bundle_closing_kit(ttype: str, docs: list) -> list:
    ddir = os.path.join("/tmp", f"kit_{ttype}")
    os.makedirs(ddir, exist_ok=True)
    for d in docs:
        os.replace(d, os.path.join(ddir, os.path.basename(d)))
    z = os.path.join("/tmp", f"{ttype}_closing_kit.zip")
    with zipfile.ZipFile(z, "w") as zf:
        for fn in os.listdir(ddir):
            zf.write(os.path.join(ddir, fn), arcname=fn)
    logger.info(f"Closing kit created at {z}")
    return [z]
