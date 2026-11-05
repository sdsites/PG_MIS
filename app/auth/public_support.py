"""Public web/mobile support tickets and Superadmin ticket management for PG MIS.

Registered through the existing auth blueprint in app/auth/routes.py:

    from .public_support import register_public_support, handle_web_login_support
    register_public_support(auth_bp)

No additional registration or modification of routes.py is required.

All ticket submissions (web and mobile) go to the same MongoDB collection.
"""

import json
import os
import re
import secrets
from datetime import datetime, timedelta
from pathlib import Path

from flask import (
    abort, current_app, flash, jsonify, redirect, render_template, request,
    send_file, session, url_for,
)
from werkzeug.utils import secure_filename

from ..rbac import roles_required

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
MAX_ATTACHMENTS = 5  # Mobile API remains backwards-compatible; web form offers one file.
REF_RE = re.compile(r"^PGMIS-\d{8}-[A-F0-9]{12}$")
STATUSES = ("Open", "In Progress", "Waiting for User", "Resolved", "Closed")
PRIORITIES = ("Low", "Normal", "High", "Urgent")


def _tickets():
    return current_app.mongo_db.pgmis_login_support_tickets


def _clean(value, length):
    return str(value or "").strip()[:length]


def _valid_mobile(value):
    return re.fullmatch(r"[0-9]{10}", str(value or "")) is not None


def _utc(value):
    return value.isoformat() + "Z" if isinstance(value, datetime) else str(value or "")


def _user_ip():
    # Do not trust X-Forwarded-For from untrusted public clients.
    return request.remote_addr or "unknown"


def _validate_fields(data):
    """Only 4 required fields; preserve optional historical/mobile fields.

    The previous web/mobile API required account_type and subject. Both are
    automatically derived when missing, without changing values from old clients.
    """
    fields = {
        "name": _clean(data.get("name"), 120),
        "mobile": _clean(data.get("mobile"), 15),
        "email": _clean(data.get("email"), 180),
        "account_type": _clean(data.get("account_type"), 100) or "Other",
        "username": _clean(data.get("username"), 120),
        "problem_type": _clean(data.get("problem_type"), 120),
        "subject": _clean(data.get("subject"), 180),
        "details": _clean(data.get("details"), 3000),
    }
    if any(not fields[k] for k in ("name", "mobile", "problem_type", "details")):
        raise ValueError("Please complete your name, mobile, issue type and description.")
    if not _valid_mobile(fields["mobile"]):
        raise ValueError("A valid 10-digit mobile number is required.")
    if fields["email"] and not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", fields["email"]):
        raise ValueError("Please enter a valid email address.")
    if fields["account_type"] not in ACCOUNT_TYPES:
        raise ValueError("Invalid account type.")
    if fields["problem_type"] not in PROBLEM_TYPES:
        raise ValueError("Please select a valid issue type.")
    if not fields["subject"]:
        fields["subject"] = fields["problem_type"]
    return fields


def _read_attachments(files):
    """Validate size before saving private attachments."""
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

    # Server-side public rate limits: still apply to simplified web submissions.
    if tickets.count_documents({
        "created_ip": _user_ip(),
        "created_at": {"$gte": now - timedelta(hours=1)},
    }) >= 5:
        raise ValueError("Too many support requests. Please try again later.")
    if tickets.count_documents({
        "mobile": fields["mobile"],
        "created_at": {"$gte": now - timedelta(days=1)},
    }) >= 5:
        raise ValueError("Too many tickets for this mobile number today.")

    reference = f"PGMIS-{now:%Y%m%d}-{secrets.token_hex(6).upper()}"
    directory = Path(current_app.instance_path) / "private_support_uploads" / reference
    uploaded = []
    if uploads:
        directory.mkdir(parents=True, exist_ok=False)
    try:
        for filename, ext, payload in uploads:
            stored = secrets.token_hex(12) + ext
            # Stored outside static/ and uploads/; retrieval is Superadmin-only.
            with (directory / stored).open("xb") as stream:
                stream.write(payload)
            uploaded.append({"name": filename, "stored_name": stored, "size": len(payload)})
        doc = {
            **fields,
            "reference": reference,
            "status": "Open",
            "priority": "Normal",
            "source": "web" if request.path.rstrip("/").endswith("login-support") else "mobile_or_api",
            "created_at": now,
            "updated_at": now,
            "created_ip": _user_ip(),
            "latest_update": "Ticket received. The support team will review your request.",
            "attachments": uploaded,
            "history": [{"author": "System", "message": "Support request received.", "at": _utc(now)}],
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
    """Public response deliberately excludes mobile, email, IP and stored filenames."""
    return {
        "reference": doc["reference"],
        "status": doc.get("status", "Open"),
        "subject": doc.get("subject", ""),
        "created_at": _utc(doc.get("created_at")),
        "updated_at": _utc(doc.get("updated_at")),
        "latest_update": doc.get("latest_update", ""),
        "history": [
            {"author": _clean(e.get("author"), 40),
             "message": _clean(e.get("message"), 2000),
             "at": _utc(e.get("at"))}
            for e in doc.get("history", [])[-50:]
        ],
    }


def _limit_public_lookups():
    """Count both successful and failed public lookup attempts per IP."""
    now = datetime.utcnow()
    logs = current_app.mongo_db.pgmis_support_lookup_attempts
    ip = _user_ip()
    if logs.count_documents({"ip": ip, "created_at": {"$gte": now - timedelta(hours=1)}}) >= 40:
        raise ValueError("Too many tracking requests. Please try later.")
    logs.insert_one({"ip": ip, "created_at": now})


def _submit_requester_reply(reference, mobile, reply_text):
    reference = _clean(reference, 40).upper()
    mobile = _clean(mobile, 15)
    reply_text = _clean(reply_text, 1000)
    if not _valid_mobile(mobile) or not reply_text:
        raise ValueError("Mobile number and a reply are required.")
    _limit_public_lookups()
    doc = _find_ticket(reference, mobile)
    if not doc:
        raise LookupError("No ticket found for this reference and mobile number.")
    if doc.get("status", "Open") in ("Resolved", "Closed"):
        raise RuntimeError("This ticket is resolved or closed. Please create a new request.")
    recent = [e for e in doc.get("history", []) if e.get("author") == "Requester"]
    if len(recent) >= 20:
        raise ValueError("Reply limit reached. Please contact support directly.")
    now = datetime.utcnow()
    _tickets().update_one({"_id": doc["_id"]}, {
        "$push": {"history": {"author": "Requester", "message": reply_text, "at": _utc(now)}},
        "$set": {"updated_at": now, "latest_update": "Additional information received from requester."},
    })
    return _find_ticket(reference, mobile)


def register_public_support(auth_bp):
    """Register public endpoints + Superadmin management in the existing blueprint."""

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
            data = request.get_json(silent=True) if request.is_json else request.form
            ticket = _create_ticket(data or {}, request.files.getlist("attachments"))
            return jsonify({**ticket, "message": "Ticket submitted successfully."}), 201
        except ValueError as error:
            return jsonify({"error": str(error)}), 400
        except Exception:
            current_app.logger.exception("Public support ticket creation failed")
            return jsonify({"error": "Unable to create the support ticket right now."}), 500

    @auth_bp.route("/public/support/track", methods=["POST"])
    def public_support_track():
        data = request.get_json(silent=True) or {}
        reference = _clean(data.get("reference"), 40).upper()
        mobile = _clean(data.get("mobile"), 15)
        if not REF_RE.fullmatch(reference) or not _valid_mobile(mobile):
            return jsonify({"error": "Ticket reference and registered 10-digit mobile are required."}), 400
        try:
            _limit_public_lookups()
        except ValueError as error:
            return jsonify({"error": str(error)}), 429
        doc = _find_ticket(reference, mobile)
        if not doc:
            return jsonify({"error": "No ticket found for this reference and mobile number."}), 404
        response = jsonify({"ticket": _public_ticket(doc)})
        response.headers["Cache-Control"] = "no-store"
        return response

    @auth_bp.route("/public/support/tickets/<reference>/reply", methods=["POST"])
    def public_support_reply(reference):
        data = request.get_json(silent=True) or {}
        try:
            _submit_requester_reply(reference, data.get("mobile"), data.get("message"))
        except LookupError:
            return jsonify({"error": "No ticket found for this reference and mobile number."}), 404
        except RuntimeError as error:
            return jsonify({"error": str(error)}), 409
        except ValueError as error:
            return jsonify({"error": str(error)}), 429 if "limit" in str(error).lower() or "too many" in str(error).lower() else 400
        return jsonify({"message": "Your reply was saved."})

    # SUPERADMIN ROUTES -- web session and role enforced server-side.
    @auth_bp.route("/support/tickets", methods=["GET"])
    @roles_required("SUPER_ADMIN")
    def support_tickets_admin():
        status = _clean(request.args.get("status"), 30)
        search = _clean(request.args.get("q"), 100)
        query = {}
        if status in STATUSES:
            query["status"] = status
        if search:
            pattern = re.escape(search)
            query["$or"] = [
                {"reference": {"$regex": pattern, "$options": "i"}},
                {"name": {"$regex": pattern, "$options": "i"}},
                {"mobile": {"$regex": pattern, "$options": "i"}},
                {"subject": {"$regex": pattern, "$options": "i"}},
            ]
        items = list(_tickets().find(query).sort("created_at", -1).limit(200))
        counts = {s: _tickets().count_documents({"status": s}) for s in STATUSES}
        return render_template(
            "support_admin_tickets.html", tickets=items, counts=counts,
            selected_status=status, search=search, statuses=STATUSES,
        )

    @auth_bp.route("/support/tickets/<reference>", methods=["GET"])
    @roles_required("SUPER_ADMIN")
    def support_ticket_detail_admin(reference):
        doc = _tickets().find_one({"reference": _clean(reference, 40).upper()}) if REF_RE.fullmatch(reference.upper()) else None
        if doc is None:
            abort(404)
        support_csrf = session.get("_pgmis_support_csrf")
        if not support_csrf:
            support_csrf = secrets.token_urlsafe(32)
            session["_pgmis_support_csrf"] = support_csrf
        return render_template(
            "support_admin_detail.html", ticket=doc, statuses=STATUSES,
            priorities=PRIORITIES, support_csrf=support_csrf,
        ), 200, {"Cache-Control": "private, no-store"}

    @auth_bp.route("/support/tickets/<reference>/update", methods=["POST"])
    @roles_required("SUPER_ADMIN")
    def support_ticket_update_admin(reference):
        # Explicit CSRF protection for admin actions, even if global CSRF is off.
        expected = session.get("_pgmis_support_csrf", "")
        supplied = request.form.get("_support_csrf", "")
        if not expected or not supplied or not secrets.compare_digest(expected, supplied):
            abort(403)
        if not REF_RE.fullmatch(reference.upper()):
            abort(404)
        doc = _tickets().find_one({"reference": reference.upper()})
        if doc is None:
            abort(404)
        status = _clean(request.form.get("status"), 40)
        priority = _clean(request.form.get("priority"), 20)
        reply = _clean(request.form.get("reply"), 2000)
        if status not in STATUSES or priority not in PRIORITIES:
            flash("Select a valid ticket status and priority.", "danger")
            return redirect(url_for("auth.support_ticket_detail_admin", reference=reference))

        status_changed = status != doc.get("status", "Open")
        priority_changed = priority != doc.get("priority", "Normal")
        if not reply and not status_changed and not priority_changed:
            flash("No changes to save.", "info")
            return redirect(url_for("auth.support_ticket_detail_admin", reference=reference))

        now = datetime.utcnow()
        updates = {"status": status, "priority": priority, "updated_at": now,
                   "updated_by": _clean(session.get("username"), 120) or "Superadmin"}
        history = []
        if status_changed:
            history.append({"author": "System", "message": f"Ticket status changed to {status}.", "at": _utc(now)})
        if reply:
            history.append({"author": "Support Team", "message": reply, "at": _utc(now)})
        if reply:
            updates["latest_update"] = reply
        elif status_changed:
            updates["latest_update"] = f"Ticket status changed to {status}."

        update = {"$set": updates}
        if history:
            update["$push"] = {"history": {"$each": history}}
        _tickets().update_one({"_id": doc["_id"]}, update)
        flash("Ticket updated successfully.", "success")
        return redirect(url_for("auth.support_ticket_detail_admin", reference=reference))

    @auth_bp.route("/support/tickets/<reference>/files/<stored_name>", methods=["GET"])
    @roles_required("SUPER_ADMIN")
    def support_ticket_attachment_admin(reference, stored_name):
        reference = reference.upper()
        if not REF_RE.fullmatch(reference) or stored_name != os.path.basename(stored_name):
            abort(404)
        doc = _tickets().find_one({"reference": reference})
        if doc is None:
            abort(404)
        meta = next((a for a in doc.get("attachments", []) if a.get("stored_name") == stored_name), None)
        if meta is None:
            abort(404)
        path = Path(current_app.instance_path) / "private_support_uploads" / reference / stored_name
        if not path.is_file():
            abort(404)
        response = send_file(path, as_attachment=True, download_name=meta.get("name") or "attachment")
        response.headers["Cache-Control"] = "private, no-store"
        return response


def handle_web_login_support():
    """Existing /auth/login-support route: four-field create, track and reply."""
    if request.method == "GET":
        return render_template("login_support.html")

    action = _clean(request.form.get("support_action"), 12)
    try:
        if action == "track":
            _limit_public_lookups()
            reference = _clean(request.form.get("ticket_reference"), 40).upper()
            mobile = _clean(request.form.get("mobile"), 15)
            doc = _find_ticket(reference, mobile)
            if doc is None:
                flash("No ticket found for that reference and mobile number.", "danger")
                return render_template("login_support.html", tracking_open=True)
            response = render_template(
                "login_support.html", ticket=_public_ticket(doc), track_mobile=mobile, tracking_open=True,
            )
            return response, 200, {"Cache-Control": "no-store"}

        if action == "create":
            info = _create_ticket(request.form, request.files.getlist("attachments"))
            flash("Ticket submitted successfully. Please save the reference number.", "success")
            return render_template("login_support.html", ticket={
                **info, "latest_update": "Your ticket has been received."
            }, tracking_open=True)

        if action == "reply":
            reference = _clean(request.form.get("ticket_reference"), 40).upper()
            mobile = _clean(request.form.get("mobile"), 15)
            doc = _submit_requester_reply(reference, mobile, request.form.get("message"))
            flash("Your reply has been added to the ticket.", "success")
            return render_template(
                "login_support.html", ticket=_public_ticket(doc), track_mobile=mobile, tracking_open=True,
            ), 200, {"Cache-Control": "no-store"}

        flash("Invalid support action.", "danger")
    except LookupError:
        flash("No ticket found for that reference and mobile number.", "danger")
    except RuntimeError as error:
        flash(str(error), "danger")
    except ValueError as error:
        flash(str(error), "danger")
    except Exception:
        current_app.logger.exception("Web login support failed")
        flash("Unable to process the request at this time.", "danger")
    return render_template("login_support.html", tracking_open=(action != "create"))
