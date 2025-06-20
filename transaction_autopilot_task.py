# transaction_autopilot_task.py
import os
import sys
import json
import logging
import zipfile
from supabase import create_client
from docxtpl import DocxTemplate
import docx2txt
import pytesseract
from pdf2image import convert_from_path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_supabase():
    return create_client(
      os.environ["SUPABASE_URL"],
      os.environ["SUPABASE_SERVICE_ROLE_KEY"]
    )

def generate_document(template_name, context, prefix):
    tpl = DocxTemplate(os.path.join("templates/transaction_autopilot", template_name))
    tpl.render(context)
    out = os.path.join("/tmp", f"{prefix}_{context['id']}.docx")
    tpl.save(out)
    logger.info(f"Generated {out}")
    return out

def bundle_closing_kit(ttype, docs):
    kit_dir = os.path.join("/tmp", f"kit_{ttype}")
    os.makedirs(kit_dir, exist_ok=True)
    for doc in docs:
        os.replace(doc, os.path.join(kit_dir, os.path.basename(doc)))
    zip_path = os.path.join("/tmp", f"{ttype}_closing_kit.zip")
    with zipfile.ZipFile(zip_path, "w") as zf:
        for fname in os.listdir(kit_dir):
            zf.write(os.path.join(kit_dir, fname), arcname=fname)
    logger.info(f"Zipped kit at {zip_path}")
    return [zip_path]

def main():
    if len(sys.argv) != 2:
        logger.error("Usage: python transaction_autopilot_task.py <payload.json>")
        sys.exit(1)

    payload = json.loads(open(sys.argv[1]).read())
    tx_id   = payload["data"]["id"]
    ttype   = payload["transaction_type"]
    data    = payload["data"]

    supabase = get_supabase()

    # 1) generate docs
    docs = [
        generate_document("loi_template.docx", data, "LOI"),
        generate_document("psa_template.docx", data, "PSA")
    ]

    # 2) bundle
    zip_paths = bundle_closing_kit(ttype, docs)

    # 3) upload + persist URL
    for zp in zip_paths:
        fn = os.path.basename(zp)
        with open(zp, "rb") as f:
            try:
                supabase.storage.from_("closing-kits").upload(fn, f)
            except Exception:
                pass
        public_url = f"{os.environ['SUPABASE_URL']}/storage/v1/object/public/closing-kits/{fn}"
        supabase.table("transactions") \
                 .update({"kit_url": public_url}) \
                 .eq("id", tx_id) \
                 .execute()
        logger.info(f"Stored kit_url on txn {tx_id}: {public_url}")

if __name__ == "__main__":
    main()
