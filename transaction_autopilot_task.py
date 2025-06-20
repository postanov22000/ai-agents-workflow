import os, zipfile, logging
from supabase import create_client
from docxtpl import DocxTemplate
import docx2txt, pytesseract
from pdf2image import convert_from_path

logger = logging.getLogger(__name__)

def get_supabase():
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
    return create_client(url, key)

def generate_document(template_name, context, prefix):
    tpl = DocxTemplate(os.path.join("templates/transaction_autopilot", template_name))
    tpl.render(context)
    out = os.path.join("/tmp", f"{prefix}_{context['id']}.docx")
    tpl.save(out)
    return out

def error_hunting(paths):
    # ... same as before ...
    return {}

def bundle_closing_kit(ttype, docs):
    # ... same as before ...
    return ["/tmp/kit.zip"]

def trigger_autopilot_task(transaction_type, data):
    supabase = get_supabase()
    tx_id = data["id"]

    # 1) generate
    docs = [ generate_document("loi_template.docx", data, "LOI"),
             generate_document("psa_template.docx", data, "PSA") ]

    # 2) scan (optional)
    errs = error_hunting(docs)
    if errs: logger.warning("Missing keywords: %s", errs)

    # 3) bundle
    zip_paths = bundle_closing_kit(transaction_type, docs)

    # 4) upload + persist
    public_url = None
    for zp in zip_paths:
        fn = os.path.basename(zp)
        with open(zp,"rb") as f:
            try:
                supabase.storage.from_("closing-kits").upload(fn, f)
            except:
                pass
        public_url = f"{os.environ['SUPABASE_URL']}/storage/v1/object/public/closing-kits/{fn}"
        supabase.table("transactions").update({"kit_url": public_url})\
                   .eq("id", tx_id).execute()

    return public_url
