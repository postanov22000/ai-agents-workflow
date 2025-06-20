# transaction_autopilot.py
import os
import logging
from flask import Blueprint, request, jsonify
from supabase import create_client
from redis import Redis
from rq import Queue
from rq.job import Job
from transaction_autopilot_task import trigger_autopilot_task

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

# ── RQ / Redis Setup ─────────────────────────────────────────────────────────
redis_conn = Redis.from_url(os.environ["REDIS_URL"])
rq_queue   = Queue("autopilot", connection=redis_conn)

# ── Blueprint ───────────────────────────────────────────────────────────────
bp = Blueprint("transaction_autopilot", __name__, url_prefix="/autopilot")

@bp.route("/trigger", methods=["POST"])
def trigger_autopilot():
    payload = request.json or {}

    # 0) must have transaction ID
    tx_id = payload.get("data", {}).get("id")
    if not tx_id:
        return jsonify({"status": "error", "message": "Missing transaction ID"}), 400

    # 1) enqueue the heavy work
    job = rq_queue.enqueue(
        trigger_autopilot_task,
        payload["transaction_type"],
        payload["data"],
        job_timeout="10m"
    )

    return jsonify({"status": "queued", "job_id": job.get_id()}), 202

@bp.route("/trigger/status/<job_id>", methods=["GET"])
def trigger_status(job_id):
    try:
        job = Job.fetch(job_id, connection=redis_conn)
    except Exception:
        return jsonify({"status": "unknown job"}), 404

    if job.is_finished:
        return jsonify({"status": "finished", "url": job.result}), 200
    elif job.is_failed:
        return jsonify({"status": "failed", "error": str(job.exc_info)}), 500
    else:
        return jsonify({"status": "pending"}), 202
