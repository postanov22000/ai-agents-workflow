import os
import logging
import zipfile
import shutil
from flask import Blueprint, request, jsonify
from supabase import create_client
from docxtpl import DocxTemplate
import docx2txt
import pytesseract
from pdf2image import convert_from_path

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def get_supabase_client():
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY")
    if not url or not key:
        raise RuntimeError("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set")
    return create_client(url, key)

supabase = get_supabase_client()
bp = Blueprint("transaction_autopilot", __name__)

@bp.route("/trigger-all", methods=["POST"])
def trigger_all_autopilots():
    try:
        res = supabase.table("transactions").select("*").is_("kit_url", "null").execute()
        txns = res.data or []
    except Exception as e:
        logger.error("Failed to fetch transactions: %s", e)
        return jsonify(status="error", message="Fetch failed"), 500

    processed = []
    for txn in txns:
        try:
            out = trigger_autopilot_from_payload({
                "transaction_type": txn.get("transaction_type", "generic"),
                "data": txn
            })
            if out.get("status") == "success":
                processed.append(txn["id"])
        except Exception as e:
            logger.warning("Failed to process %s: %s", txn["id"], e)

    return jsonify(status="ok", processed=processed), 200

@bp.route("/trigger", methods=["POST"])
def trigger_one_autopilot():
    payload = request.get_json(force=True)
    try:
        result = trigger_autopilot_from_payload(payload)
        return jsonify(status="success", **result), 200
    except Exception as e:
        logger.error("trigger failed: %s", e, exc_info=True)
        return jsonify(status="error", message=str(e)), 500

def trigger_autopilot_from_payload(payload: dict) -> dict:
    tx_id = payload["data"]["id"]
    ttype = payload.get("transaction_type", "generic")
    data  = payload["data"]

    docs = [
        generate_document("loi_template.docx", data, "LOI"),
        generate_document("psa_template.docx", data, "PSA"),
        generate_document("purchase_offer_template.docx", data, "PO"),
        generate_document("agency_disclosure_template.docx", data, "AD"),
        generate_document("real_estate_purchase_template.docx", data, "REP"),
        generate_document("lease_template.docx", data, "LEASE"),
        generate_document("seller_disclosure_template.docx", data, "SD"),
    ]

    zips = bundle_closing_kit(ttype, tx_id, docs)
    uploaded = []
    for zip_path in zips:
        key = os.path.basename(zip_path)
        with open(zip_path, "rb") as f:
            try:
                supabase.storage.from_("closing-kits").upload(key, f)
            except Exception as e:
                logger.warning("Upload failed (reusing): %s", e)

        pu = supabase.storage.from_("closing-kits").get_public_url(key)
        url = pu.get("publicUrl") if isinstance(pu, dict) else pu

        supabase.table("transactions").update({"kit_url": url}).eq("id", tx_id).execute()
        uploaded.append(key)

    return {"status":"success", "files": uploaded}

def generate_document(template_name: str, context: dict, prefix: str) -> str:
    tpl = DocxTemplate(os.path.join("templates/transaction_autopilot", template_name))
    tpl.render(context)
    out = os.path.join("/tmp", f"{prefix}_{context['id']}.docx")
    tpl.save(out)
    logger.info("Generated %s", out)
    return out

def bundle_closing_kit(ttype: str, tx_id: str, docs: list) -> list:
    kit_dir = os.path.join("/tmp", f"kit_{ttype}_{tx_id}")
    if os.path.isdir(kit_dir):
        shutil.rmtree(kit_dir)
    os.makedirs(kit_dir)

    for doc in docs:
        shutil.move(doc, os.path.join(kit_dir, os.path.basename(doc)))

    zip_name = f"{ttype}_{tx_id}_closing_kit.zip"
    zip_path = os.path.join("/tmp", zip_name)
    if os.path.exists(zip_path):
        os.remove(zip_path)

    with zipfile.ZipFile(zip_path, "w") as zf:
        for fname in os.listdir(kit_dir):
            zf.write(os.path.join(kit_dir, fname), arcname=fname)

    logger.info("Created ZIP %s", zip_path)
    return [zip_path]
