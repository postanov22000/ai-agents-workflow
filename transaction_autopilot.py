import os
import logging
import zipfile
from flask import Blueprint, request
from supabase import create_client
from docxtpl import DocxTemplate
import docx2txt
import pytesseract
from pdf2image import convert_from_path

# ── Logging ──────────────────────────────────────────────────────────────────
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# ── Supabase Client Setup ────────────────────────────────────────────────────
def get_supabase_client():
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY")
    if not url or not key:
        raise RuntimeError("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set")
    return create_client(url, key)

supabase = get_supabase_client()

bp = Blueprint("transaction_autopilot", __name__)

# ── Trigger Endpoint ─────────────────────────────────────────────────────────
@bp.route("/trigger", methods=["POST"])
def trigger_autopilot():
    payload = request.json or {}

    # 0) Get the transaction ID
    tx_id = payload.get("data", {}).get("id")
    if not tx_id:
        return {"status": "error", "message": "Missing transaction ID"}, 400

    ttype = payload.get("transaction_type", "generic")
    data  = payload.get("data", {})

    # 1) Generate LOI & PSA .docx
    try:
        loi_path = generate_document("loi_template.docx", data, "LOI")
        psa_path = generate_document("psa_template.docx", data, "PSA")
        docs = [loi_path, psa_path]
    except Exception as e:
        logger.error(f"Document assembly failed: {e}")
        return {"status": "error", "message": str(e)}, 500

    # 2) (Optional) Check for missing keywords
    errors = error_hunting(docs)
    if errors:
        logger.warning(f"Keywords missing in some docs: {errors}")

    # 3) Bundle into a single ZIP
    try:
        kit_zip_list = bundle_closing_kit(ttype, docs)
    except Exception as e:
        logger.error(f"Bundling failed: {e}")
        return {"status": "error", "message": str(e)}, 500

    # 4) Upload ZIP → Supabase + persist kit_url
    public_url = None
    for zip_path in kit_zip_list:
        filename = os.path.basename(zip_path)
        # bucket path: closing-kits/{filename}
        with open(zip_path, "rb") as f:
            try:
                supabase.storage.from_("closing-kits").upload(filename, f)
            except Exception as exc:
                logger.warning(f"Upload error for {filename}: {exc}; assuming it already exists")

        # Build public link
        public_url = (
            f"{os.environ['SUPABASE_URL']}"
            f"/storage/v1/object/public/closing-kits/{filename}"
        )

        # Persist kit_url back to the transaction row
        try:
            supabase.table("transactions") \
                     .update({"kit_url": public_url}) \
                     .eq("id", tx_id) \
                     .execute()
        except Exception as exc:
            logger.error(f"Failed updating txn {tx_id} with kit_url: {exc}")

    # 5) Return a tiny HTML fragment for HTMX to inject a Download button
    download_link = f'''
      <a href="{public_url}" class="btn btn-success" target="_blank">
        <i class="fas fa-download"></i> Download Closing Kit
      </a>
    '''
    return download_link, 200, {"Content-Type": "text/html"}


# ── Helpers ────────────────────────────────────────────────────────────────────
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
                logger.error(f"OCR failed for {path}: {e}")
                continue
        else:
            logger.warning(f"Unsupported file for error hunting: {path}")
            continue

        missing = [kw for kw in ("signature","date","buyer","seller") if kw not in text.lower()]
        if missing:
            results[path] = missing
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
    logger.info(f"Created ZIP at {zip_path}")
    return [zip_path]
