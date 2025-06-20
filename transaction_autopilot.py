import os
import logging
import zipfile

from flask import Blueprint, request, jsonify
from supabase import create_client
from docxtpl import DocxTemplate
import docx2txt
import pytesseract
from pdf2image import convert_from_path

from redis import Redis
from rq import Queue
from rq.job import Job

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

# ── Redis + RQ Setup (with TLS for Upstash) ─────────────────────────────────
redis_conn = Redis.from_url(
    os.environ["REDIS_URL"],
    ssl=True,
    ssl_cert_reqs=None,    # Upstash cert is publicly trusted
    decode_responses=True
)
rq_queue = Queue("autopilot", connection=redis_conn)

# ── Blueprint ────────────────────────────────────────────────────────────────
bp = Blueprint("transaction_autopilot", __name__)

# ── Enqueue endpoint ─────────────────────────────────────────────────────────
@bp.route("/trigger", methods=["POST"])
def trigger_autopilot():
    payload = request.json or {}
    tx_id = payload.get("data", {}).get("id")
    if not tx_id:
        return jsonify({"status": "error", "message": "Missing transaction ID"}), 400

    # enqueue the background job (timeout 5m)
    job = rq_queue.enqueue(
        "transaction_autopilot_task.trigger_autopilot_task",
        payload["transaction_type"],
        payload["data"],
        job_timeout="5m"
    )

    return jsonify({
        "status": "queued",
        "job_id": job.get_id()
    }), 202

# ── Status poll endpoint ─────────────────────────────────────────────────────
@bp.route("/trigger/status/<job_id>")
def trigger_status(job_id):
    try:
        job = Job.fetch(job_id, connection=redis_conn)
    except Exception:
        return jsonify({"status": "not_found"}), 404

    if job.is_finished:
        # job.result is the public_url returned from the task
        return jsonify({"status": "finished", "url": job.result}), 200
    if job.is_failed:
        return jsonify({"status": "failed", "error": str(job.exc_info)}), 500
    return jsonify({"status": "pending"}), 202

# ── (You must still register this blueprint in your app: `app.register_blueprint(bp, url_prefix="/autopilot")`) ──
