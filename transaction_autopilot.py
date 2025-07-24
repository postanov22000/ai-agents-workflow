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

@bp.route("/trigger-all", methods=["POST"])
def trigger_all_autopilots():
    try:
        res = supabase.table("transactions").select("*").is_("kit_url", "null").execute()
        transactions = res.data or []
    except Exception as e:
        logger.error(f"Failed to fetch transactions: {e}")
        return jsonify({"status": "error", "message": "Failed to fetch transactions"}), 500

    processed = []
    for txn in transactions:
        try:
            response = trigger_autopilot_from_payload({
                "transaction_type": txn.get("transaction_type", "generic"),
                "data": txn
            })
            if response.get("status") == "success":
                processed.append(txn["id"])
        except Exception as e:
            logger.warning(f"Failed to process transaction {txn['id']}: {e}")

    return jsonify({"status": "ok", "processed": processed}), 200


def trigger_autopilot_from_payload(payload: dict) -> dict:
    tx_id = payload.get("data", {}).get("id")
    ttype = payload.get("transaction_type", "generic")
    data = payload.get("data", {})

    docs = [
    generate_document("loi_template.docx", data, "LOI"),
    generate_document("psa_template.docx", data, "PSA"),
    generate_document("purchase_offer_template.docx", data, "PURCHASE_OFFER"),
    generate_document("agency_disclosure_template.docx", data, "AGENCY_DISCLOSURE"),
    generate_document("real_estate_purchase_template.docx", data, "REAL_ESTATE_PURCHASE"),
    # future:
    # generate_document("lease_template.docx", data, "LEASE"),
    # generate_document("seller_disclosure_template.docx", data, "SELLER_DISCLOSURE"),
]

    kit_zip_list = bundle_closing_kit(ttype, docs)
    uploaded_files = []

    for zip_path in kit_zip_list:
        filename = os.path.basename(zip_path)
        public_url = (
            f"{os.environ['SUPABASE_URL']}/storage/v1/object/closing-kits/{filename}"
        )
        with open(zip_path, "rb") as f:
            try:
                supabase.storage.from_("closing-kits").upload(filename, f)
            except Exception as e:
                logger.warning(f"Upload failed for {filename}: {e}, reusing existing object")

        try:
            supabase.table("transactions") \
                     .update({"kit_url": public_url}) \
                     .eq("id", tx_id) \
                     .execute()
        except Exception as e:
            logger.error(f"Failed to update transaction {tx_id} with kit_url: {e}")

        uploaded_files.append(filename)

    return {"status": "success", "files": uploaded_files}



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
