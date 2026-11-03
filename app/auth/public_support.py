"""PG MIS public Support + Privacy JSON API.

Add to app/auth/routes.py immediately after creation of auth_bp:
    from .public_support import register_public_support, handle_web_login_support
    register_public_support(auth_bp)

Then update the existing login_support() route to:
    return handle_web_login_support()

All app and web tickets are written into the same MongoDB collection.
Assumes the existing auth blueprint serves /auth/login; these routes become
/auth/public/... . Requires Flask, Werkzeug and current_app.mongo_db.
"""

import json
import os
import re
import secrets
from datetime import datetime, timedelta
from pathlib import Path

from flask import current_app, jsonify, render_template, request, flash, url_for, redirect
from werkzeug.utils import secure_filename

ACCOUNT_TYPES = [
    "Project / State / District User", "Block Admin", "CLF User",
    "Community Cadre", "PG User", "Reviewer / Validator", "Other",
]
PROBLEM_TYPES = [
    "Invalid username or password", "Account inactive / locked",
    "Unable to access assigned PG / CLF", "Role / permission issue",
    "Mobile app login issue", "Session / repeated logout issue", "Other login issue",
]
SUPPORT_EMAIL = "ites@sayanant.com"
SUPPORT_PHONE = "9957367398"
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".pdf", ".doc", ".docx"}
MAX_ATTACHMENT_SIZE = 5 * 1024 * 1024
MAX_ATTACHMENTS = 5
REF_RE = re.compile(r"^PGMIS-\d{8}-[A-F0-9]{12}$")


def _tickets():
    return current_app.mongo_db.pgmis_login_support_tickets


def _clean(value, length):
    return str(value or "").strip()[:length]


def _valid_mobile(value):
    return re.fullmatch(r"[0-9]{10}", str(value or "")) is not None


def _utc(value):
    return value.isoformat() + "Z" if isinstance(value, datetime) else str(value or "")


def _user_ip():
    # Do not blindly trust X-Forwarded-For supplied by clients.
    return request.remote_addr or "unknown"


def _validate_fields(data):
    required = ("name", "mobile", "account_type", "problem_type", "subject", "details")
    fields = {
        "name": _clean(data.get("name"), 120),
        "mobile": _clean(data.get("mobile"), 15),
        "email": _clean(data.get("email"), 180),
        "account_type": _clean(data.get("account_type"), 100),
        "username": _clean(data.get("username"), 120),
        "problem_type": _clean(data.get("problem_type"), 120),
        "subject": _clean(data.get("subject"), 180),
        "details": _clean(data.get("details"), 3000),
    }
    if any(not fields[k] for k in required):
        raise ValueError("All required fields must be completed.")
    if not _valid_mobile(fields["mobile"]):
        raise ValueError("A valid 10-digit mobile number is required.")
    if fields["email"] and not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", fields["email"]):
        raise ValueError("Please enter a valid email address.")
    if fields["account_type"] not in ACCOUNT_TYPES or fields["problem_type"] not in PROBLEM_TYPES:
        raise ValueError("Invalid account type or problem type.")
    return fields


def _read_attachments(files):
    """Validate before writing any file, avoiding unbounded streaming to disk."""
    if len(files) > MAX_ATTACHMENTS:
        raise ValueError("Maximum 5 attachments permitted.")
    prepared = []
    for file in files:
        if not file or not file.filename:
            continue
        filename = secure_filename(file.filename)
        extension = os.path.splitext(filename)[1].lower()
        if not filename or extension not in ALLOWED_EXTENSIONS:
            raise ValueError("Allowed file types: PNG, JPG, WEBP, PDF, DOC, DOCX.")
        payload = file.stream.read(MAX_ATTACHMENT_SIZE + 1)
        if len(payload) > MAX_ATTACHMENT_SIZE:
            raise ValueError("Each attachment must be 5 MB or smaller.")
        if not payload:
            raise ValueError("Empty files are not supported.")
        prepared.append((filename, extension, payload))
    return prepared


def _create_ticket(data, files):
    fields = _validate_fields(data)
    uploads = _read_attachments(files)
    now = datetime.utcnow()
    tickets = _tickets()
    # Basic server-side abuse limit for a public, unauthenticated form.
    cutoff = now - timedelta(hours=1)
    if tickets.count_documents({"created_ip": _user_ip(), "created_at": {"$gte": cutoff}}) >= 5:
        raise ValueError("Too many support requests. Please try again later.")
    if tickets.count_documents({"mobile": fields["mobile"], "created_at": {"$gte": now - timedelta(days=1)}}) >= 5:
        raise ValueError("Too many tickets for this mobile number today.")

    reference = f"PGMIS-{now:%Y%m%d}-{secrets.token_hex(6).upper()}"
    directory = Path(current_app.instance_path) / "private_support_uploads" / reference
    uploaded = []
    if uploads:
        directory.mkdir(parents=True, exist_ok=False)
    try:
        for filename, ext, payload in uploads:
            safe_name = secrets.token_hex(12) + ext
            path = directory / safe_name
            # Store uploads outside public static/upload paths; access must be staff-authorised.
            with path.open("xb") as stream:
                stream.write(payload)
            uploaded.append({"name": filename, "stored_name": safe_name, "size": len(payload)})
        doc = {
            **fields,
            "reference": reference,
            "status": "Open",
            "created_at": now,
            "updated_at": now,
            "created_ip": _user_ip(),
            "latest_update": "Ticket received. The support team will review your request.",
            "attachments": uploaded,
            "history": [
                {"author": "System", "message": "Support request received.", "at": _utc(now)},
            ],
        }
        tickets.insert_one(doc)
    except Exception:
        for item in uploaded:
            try:
                (directory / item["stored_name"]).unlink(missing_ok=True)
            except OSError:
                pass
        raise
    return {"reference": reference, "status": "Open", "created_at": _utc(now)}


def _find_ticket(reference, mobile):
    reference = _clean(reference, 40).upper()
    if not REF_RE.fullmatch(reference) or not _valid_mobile(mobile):
        return None
    return _tickets().find_one({"reference": reference, "mobile": mobile})


def _public_ticket(doc):
    return {
        "reference": doc["reference"], "status": doc.get("status", "Open"),
        "subject": doc.get("subject", ""),
        "created_at": _utc(doc.get("created_at")),
        "updated_at": _utc(doc.get("updated_at")),
        "latest_update": doc.get("latest_update", ""),
        "history": [
            {"author": _clean(e.get("author"), 40), "message": _clean(e.get("message"), 2000), "at": _utc(e.get("at"))}
            for e in doc.get("history", [])[-50:]
        ],
    }


def register_public_support(auth_bp):
    """Register under the EXISTING auth blueprint (normally mounted /auth)."""

    @auth_bp.route("/public/support/config", methods=["GET"])
    def public_support_config():
        return jsonify({
            "account_types": ACCOUNT_TYPES, "problem_types": PROBLEM_TYPES,
            "max_attachments": MAX_ATTACHMENTS, "max_attachment_mb": 5,
            "contact": {"email": SUPPORT_EMAIL, "phone": SUPPORT_PHONE},
        })

    @auth_bp.route("/public/privacy-policy", methods=["GET"])
    def public_privacy_policy_json():
        path = Path(__file__).parent / "data" / "privacy_policy.json"
        with path.open("r", encoding="utf-8") as stream:
            payload = json.load(stream)
        response = jsonify(payload)
        response.headers["Cache-Control"] = "public, max-age=3600"
        return response

    @auth_bp.route("/public/support/tickets", methods=["POST"])
    def public_support_create():
        try:
            # Multipart uploads from React Native, also supports JSON-only clients.
            data = request.get_json(silent=True) if request.is_json else request.form
            data = data or {}
            files = request.files.getlist("attachments")
            ticket = _create_ticket(data, files)
            return jsonify({**ticket, "message": "Ticket submitted successfully."}), 201
        except ValueError as error:
            return jsonify({"error": str(error)}), 400
        except Exception:
            current_app.logger.exception("Public support ticket creation failed")
            return jsonify({"error": "Unable to create the support ticket right now."}), 500

    @auth_bp.route("/public/support/track", methods=["POST"])
    def public_support_track():
        data = request.get_json(silent=True) or {}
        reference = _clean(data.get("reference"), 40)
        mobile = _clean(data.get("mobile"), 15)
        if not _valid_mobile(mobile) or not REF_RE.fullmatch(reference):
            return jsonify({"error": "Ticket reference and registered 10-digit mobile are required."}), 400
        # Brute-force protection for public ticket lookups. Never expose details
        # unless both reference and mobile match.
        now = datetime.utcnow()
        logs = current_app.mongo_db.pgmis_support_lookup_attempts
        cutoff = now - timedelta(hours=1)
        ip = _user_ip()
        if logs.count_documents({"ip": ip, "created_at": {"$gte": cutoff}}) >= 40:
            return jsonify({"error": "Too many tracking requests. Please try later."}), 429
        logs.insert_one({"ip": ip, "created_at": now})
        doc = _find_ticket(reference, mobile)
        # Do not reveal whether the reference exists for a different mobile number.
        if not doc:
            return jsonify({"error": "No ticket found for this reference and mobile number."}), 404
        response = jsonify({"ticket": _public_ticket(doc)})
        response.headers["Cache-Control"] = "no-store"
        return response

    @auth_bp.route("/public/support/tickets/<reference>/reply", methods=["POST"])
    def public_support_reply(reference):
        data = request.get_json(silent=True) or {}
        mobile = _clean(data.get("mobile"), 15)
        reply_text = _clean(data.get("message"), 1000)
        if not _valid_mobile(mobile) or not reply_text:
            return jsonify({"error": "Mobile number and reply are required."}), 400
        doc = _find_ticket(reference, mobile)
        if not doc:
            return jsonify({"error": "No ticket found for this reference and mobile number."}), 404
        if doc.get("status", "").lower() in ("closed", "resolved"):
            return jsonify({"error": "This ticket is closed. Please create a new request."}), 409
        now = datetime.utcnow()
        # Limit public replies to prevent spam.
        recent = [e for e in doc.get("history", []) if e.get("author") == "Requester"]
        if len(recent) >= 20:
            return jsonify({"error": "Reply limit reached. Please contact support directly."}), 429
        _tickets().update_one({"_id": doc["_id"]}, {"$push": {
            "history": {"author": "Requester", "message": reply_text, "at": _utc(now)}
        }, "$set": {"updated_at": now, "latest_update": "Additional information received from requester."}})
        return jsonify({"message": "Your reply was saved."})


def handle_web_login_support():
    """Upgrade the EXISTING web login support route to use the same ticket storage.
    Keep its route decorator as-is in auth/routes.py.
    """
    if request.method == "GET":
        return render_template("login_support.html")
    action = _clean(request.form.get("support_action"), 12)
    try:
        if action == "track":
            reference = _clean(request.form.get("ticket_reference"), 40)
            mobile = _clean(request.form.get("mobile"), 15)
            ticket = _find_ticket(reference, mobile)
            if not ticket:
                flash("Ticket not found for the provided reference and registered mobile.", "danger")
                return render_template("login_support.html")
            return render_template("login_support.html", ticket=_public_ticket(ticket))
        if action == "create":
            info = _create_ticket(request.form, request.files.getlist("attachments"))
            flash("Support ticket created. Save reference: " + info["reference"], "success")
            return render_template("login_support.html", ticket={
                **info, "latest_update": "Your ticket has been received."
            })
        flash("Invalid support action.", "danger")
    except ValueError as err:
        flash(str(err), "danger")
    except Exception:
        current_app.logger.exception("Web login support failed")
        flash("Unable to process the request at this time.", "danger")
    return render_template("login_support.html")
