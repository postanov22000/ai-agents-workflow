import os
import logging
import zipfile
from supabase import create_client
from docxtpl import DocxTemplate
import docx2txt
import pytesseract
from pdf2image import convert_from_path

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def get_supabase():
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY")
    if not url or not key:
        raise RuntimeError("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set")
    return create_client(url, key)

def generate_document(template_name: str, context: dict, prefix: str) -> str:
    tpl_path = os.path.join("templates", "transaction_autopilot", template_name)
    tpl = DocxTemplate(tpl_path)
    tpl.render(context)
    out_path = os.path.join("/tmp", f"{prefix}_{context['id']}.docx")
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
            logger.warning(f"Unsupported format for {path}")
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
            full = os.path.join(kit_dir, fname)
            zf.write(full, arcname=fname)
    logger.info(f"Created ZIP at {zip_path}")
    return [zip_path]

def trigger_autopilot_task(transaction_type: str, data: dict) -> str:
    """
    RQ task entrypoint. Generates, uploads & persists kit_url.
    Returns the public URL.
    """
    supabase = get_supabase()
    tx_id = data["id"]

    # 1) generate docs
    docs = [
        generate_document("loi_template.docx", data, "LOI"),
        generate_document("psa_template.docx", data, "PSA")
    ]

    # 2) optional scan
    errs = error_hunting(docs)
    if errs:
        logger.warning("Missing keywords: %s", errs)

    # 3) create ZIP
    zip_paths = bundle_closing_kit(transaction_type, docs)

    # 4) upload + persist
    public_url = None
    for zp in zip_paths:
        fn = os.path.basename(zp)
        with open(zp, "rb") as f:
            try:
                supabase.storage.from_("closing-kits").upload(fn, f)
            except Exception:
                # assume already exists
                pass

        public_url = f"{os.environ['SUPABASE_URL']}/storage/v1/object/public/closing-kits/{fn}"
        supabase.table("transactions") \
                .update({"kit_url": public_url}) \
                .eq("id", tx_id) \
                .execute()

    return public_url
