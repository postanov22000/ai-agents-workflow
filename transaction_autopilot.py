# transaction_autopilot.py
import os
import json
import logging
import requests
from flask import Blueprint, request, jsonify

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

bp = Blueprint("transaction_autopilot", __name__)

@bp.route("/trigger", methods=["POST"])
def trigger_autopilot():
    payload = request.json or {}
    tx_id = payload.get("data", {}).get("id")
    if not tx_id:
        return jsonify({"status": "error", "message": "Missing transaction ID"}), 400

    # Prepare GitHub dispatch
    repo       = os.environ["GITHUB_REPO"]    # e.g. "username/replyzeai"
    token      = os.environ["GITHUB_PAT"]     # Personal Access Token
    event_type = "autopilot-trigger"

    dispatch_body = {
        "event_type": event_type,
        "client_payload": payload
    }
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept":        "application/vnd.github+json"
    }

    resp = requests.post(
        f"https://api.github.com/repos/{repo}/dispatches",
        headers=headers,
        data=json.dumps(dispatch_body),
        timeout=10
    )

    if resp.status_code == 204:
        logger.info(f"Dispatched autopilot for txn {tx_id}")
        return jsonify({"status": "dispatched"}), 202
    else:
        logger.error(f"GitHub dispatch failed ({resp.status_code}): {resp.text}")
        return jsonify({"status": "error", "message": "Dispatch failed"}), 500
