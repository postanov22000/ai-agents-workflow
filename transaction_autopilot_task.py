# transaction_autopilot_task.py

import os
import logging
import zipfile
import tempfile
import uuid

from supabase import create_client
from docxtpl import DocxTemplate

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def _get_supabase():
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY")
    if not url or not key:
        raise RuntimeError("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set")
    return create_client(url, key)

def _render_docx(template_filename: str, context: dict, out_prefix: str) -> str:
    """
    Render a .docx template under templates/transaction_autopilot/
    into /tmp/<out_prefix>_<tx_id>_<uuid>.docx and return its path.
    """
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
    """
    Bundle the given file paths into a zip under /tmp and return its path.
    """
    zip_name = f"{tx_id}_closing_kit.zip"
    zip_path = os.path.join(tempfile.gettempdir(), zip_name)
    with zipfile.ZipFile(zip_path, "w") as zf:
        for fp in file_paths:
            zf.write(fp, arcname=os.path.basename(fp))
    logger.info("Bundled ZIP → %s", zip_path)
    return zip_path

def trigger_autopilot_task(transaction_type: str, data: dict) -> str:
    """
    Synchronous entrypoint: render LOI + PSA, zip, upload to Supabase storage,
    update the transaction row with kit_url, and return that URL.
    """
    sb = _get_supabase()
    tx_id = data["id"]

    # 1) render both templates
    docs = [
        _render_docx("loi_template.docx", data, "LOI"),
        _render_docx("psa_template.docx", data, "PSA")
    ]

    # 2) bundle into a zip
    zip_path = _bundle_zip(tx_id, docs)

    # 3) upload to Supabase Storage under "<tx_id>/" folder
    bucket = "closing-kits"
    key = f"{tx_id}/{os.path.basename(zip_path)}"
    with open(zip_path, "rb") as f:
        try:
            sb.storage.from_(bucket).upload(key, f, {"cacheControl": "3600"})
            logger.info("Uploaded zip to storage as %s", key)
        except Exception as e:
            logger.warning("Upload may already exist (ignored): %s", e)

    # 4) build public URL
    pu = sb.storage.from_(bucket).get_public_url(key)
    if isinstance(pu, dict):
        url = pu.get("publicUrl") or pu.get("PublicURL") or pu.get("url")
    else:
        url = pu

    # 5) persist kit_url back to Supabase
    sb.table("transactions") \
      .update({"kit_url": url}) \
      .eq("id", tx_id) \
      .execute()
    logger.info("Saved kit_url for transaction %s", tx_id)

    return url
