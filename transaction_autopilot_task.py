# transaction_autopilot_task.py

import os
import logging
import zipfile
import tempfile
import uuid
from datetime import date, datetime, timedelta
from supabase import create_client
from docxtpl import DocxTemplate
from collections import defaultdict

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Rate limiting storage
demo_rate_limits = defaultdict(lambda: {
    'kits': 20,  # 20 kits per month
    'last_reset': datetime.now()
})

def _get_supabase():
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY")
    if not url or not key:
        raise RuntimeError("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set")
    return create_client(url, key)

def _render_docx(template_filename: str, context: dict, out_prefix: str) -> str:
    tpl_path = os.path.join("templates", "transaction_autopilot", template_filename)
    doc = DocxTemplate(tpl_path)
    doc.render(context)
    unique = uuid.uuid4().hex[:8]
    out_name = f"{out_prefix}_{context['id']}_{unique}.docx"
    out_path = os.path.join(tempfile.gettempdir(), out_name)
    doc.save(out_path)
    logger.info("Rendered %s → %s", template_filename, out_path)
    return out_path

def _bundle_zip(tx_id: str, file_paths: list[str]) -> str:
    unique = uuid.uuid4().hex[:8]
    zip_name = f"{tx_id}_{unique}_closing_kit.zip"
    zip_path = os.path.join(tempfile.gettempdir(), zip_name)
    with zipfile.ZipFile(zip_path, "w") as zf:
        for fp in file_paths:
            zf.write(fp, arcname=os.path.basename(fp))
    logger.info("Bundled ZIP → %s", zip_path)
    return zip_path

def trigger_autopilot_task(transaction_type: str, data: dict, ip_address: str) -> str:
    """
    Render docs, zip, upload to Supabase, update transaction.kit_url,
    and enforce a 20‑kits‑per‑month rate limit.
    """
    # Check rate limit
    now = datetime.now()
    
    # Reset limits if it's a new month
    if (now - demo_rate_limits[ip_address]['last_reset']).days >= 30:
        demo_rate_limits[ip_address]['kits'] = 20
        demo_rate_limits[ip_address]['last_reset'] = now
    
    if demo_rate_limits[ip_address]['kits'] <= 0:
        raise RuntimeError("Monthly closing-kit generation limit reached")
        
    # Decrement kit count
    demo_rate_limits[ip_address]['kits'] -= 1
    
    sb = _get_supabase()
    tx_id   = data["id"]
    user_id = data.get("user_id")
    if not user_id:
        raise RuntimeError("Missing user_id in payload")

    # 1) Render all templates
    docs = [
        _render_docx("loi_template.docx", data, "LOI"),
        _render_docx("psa_template.docx", data, "PSA"),
        _render_docx("purchase_offer_template.docx", data, "PURCHASE_OFFER"),
        _render_docx("agency_disclosure_template.docx", data, "AGENCY_DISCLOSURE"),
        _render_docx("real_estate_purchase_template.docx", data, "REAL_ESTATE_PURCHASE"),
        _render_docx("lease_template.docx", data, "LEASE"),
        _render_docx("seller_disclosure_template.docx", data, "SELLER_DISCLOSURE"),
    ]

    # 2) Bundle into a uniquely‑named ZIP
    zip_path = _bundle_zip(tx_id, docs)

    # 3) Upload under "<user_id>/<tx_id>/"
    bucket     = "closing-kits"
    filename   = os.path.basename(zip_path)
    storage_key = f"{user_id}/{tx_id}/{filename}"
    with open(zip_path, "rb") as f:
        try:
            sb.storage.from_(bucket).upload(storage_key, f, {"cacheControl":"3600"})
            logger.info("Uploaded zip as %s", storage_key)
        except Exception as e:
            logger.warning("Upload may already exist, reusing: %s", e)

    # 4) Build public URL
    pu  = sb.storage.from_(bucket).get_public_url(storage_key)
    url = pu.get("publicUrl") if isinstance(pu, dict) else pu

    # 5) Persist kit_url back to Supabase
    sb.table("transactions") \
      .update({"kit_url": url}) \
      .eq("id", tx_id) \
      .execute()
    logger.info("Saved kit_url for transaction %s", tx_id)

    return url
