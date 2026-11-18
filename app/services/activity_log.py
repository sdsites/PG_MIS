"""PG MIS activity recording and safe formatting.

The new activity_events collection is append-only at the HTTP layer. Old audit_logs
remain readable; their historic snapshots are NEVER rendered verbatim. The generic
capture records ONLY metadata about accepted writes, not submitted form/JSON bodies.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta

from bson import ObjectId
from flask import current_app, g, has_request_context, request, session

SENSITIVE = re.compile(
    r"password|secret|token|otp|cookie|session|authorization|aadhaar|aadhar|pan_?no|"
    r"account_?number|bank_?account|ifsc|signature|base64|biometric|photo|"
    r"document_?data|private_?key|api_?key|card_?number|cvv|pin|contact|phone|"
    r"email|address|birth|dob|salary|beneficiary|identity|routing|reason|note|comment|description|free_text", re.I
)

CATEGORIES = {
    "authentication": "Authentication",
    "users": "User management",
    "registrations": "Registrations & members",
    "approvals": "Approvals & validation",
    "financial": "Finance & records",
    "reports": "MPR & reports",
    "documents": "Documents",
    "mapping": "Master data & mapping",
    "operations": "PG operations",
    "security": "Security",
}

# Explicit, reviewed route titles. Fallback is deliberately phrased as a
# request and not as a confirmed database change (some legacy routes use a 200
# response after validation failures).
ROUTES = {
    "auth.assign_cadre_pgs": ("mapping", "Updated cadre PG assignment", "important"),
    "auth.approve_cadre_cc": ("approvals", "Approved cadre account", "important"),
    "auth.approve_cadre_profile": ("approvals", "Approved cadre profile", "important"),
    "auth.reject_cadre_profile": ("approvals", "Rejected cadre profile", "important"),
    "auth.cadre_profile": ("users", "Submitted cadre profile update", "important"),
    "pg.pg_registration": ("registrations", "Submitted PG registration changes", "important"),
    "pg.pg_submit_for_authorization": ("approvals", "Submitted PG for authorization", "important"),
    "pg.submit_for_authorization": ("approvals", "Submitted PG for authorization", "important"),
    "pg.pg_authorization": ("approvals", "Submitted PG authorization decision", "important"),
    "pg.state_authorization": ("approvals", "Submitted state authorization decision", "important"),
    "pg.pg_members": ("registrations", "Submitted PG member changes", "important"),
    "pg.submit_pg_registration_validation": ("approvals", "Submitted PG for validation", "important"),
    "pg.submit_member_registration_validation": ("approvals", "Submitted members for validation", "important"),
    "pg.validation_approve": ("approvals", "Submitted registration approval", "important"),
    "pg.validation_reject": ("approvals", "Submitted registration rejection", "important"),
    "pg.pg_upload_document": ("documents", "Submitted PG document upload", "important"),
    "pg.api_crop_management_save": ("operations", "Saved crop management information", "important"),
    "pg.api_cashbook": ("financial", "Submitted cashbook transaction", "important"),
    "pg.api_ledger_book": ("financial", "Submitted ledger transaction", "important"),
    "pg.api_receipt_voucher": ("financial", "Submitted receipt voucher", "important"),
    "pg.api_generic_register": ("operations", "Submitted register changes", "important"),
    "pg.api_sector_loan_ledger_account": ("financial", "Submitted sector loan account", "important"),
    "pg.api_sector_loan_ledger": ("financial", "Submitted sector loan ledger changes", "important"),
    "pg.api_loan_ledger": ("financial", "Submitted loan ledger changes", "important"),
    "pg.meeting_register": ("operations", "Submitted meeting register", "important"),
    "master_data.manage_states": ("mapping", "Submitted state master changes", "important"),
    "master_data.manage_districts": ("mapping", "Submitted district master changes", "important"),
    "master_data.manage_blocks": ("mapping", "Submitted block master changes", "important"),
    "master_data.manage_clfs": ("mapping", "Submitted CLF master changes", "important"),
    "master_data.manage_pgs": ("mapping", "Submitted PG master changes", "important"),
    "master_data.manage_clf_admins": ("users", "Submitted CLF user changes", "important"),
    "master_data.toggle_clf_admin_status": ("users", "Submitted CLF account status change", "critical"),
    "master_data.clf_pg_assignment": ("mapping", "Submitted CLF-PG mapping changes", "important"),
    "master_data.shg_upload_replace": ("documents", "Submitted SHG master replacement", "critical"),
    "finance.pg_funds": ("financial", "Submitted PG funds changes", "important"),
    "finance.pg_loans": ("financial", "Submitted PG loans changes", "important"),
    "finance.loan_accounts": ("financial", "Submitted loan account changes", "important"),
    "finance.loan_account_view": ("financial", "Submitted loan account update", "important"),
    "finance.member_loan_accounts": ("financial", "Submitted member loan changes", "important"),
    "finance.member_loan_view": ("financial", "Submitted member loan update", "important"),
    "finance.grants": ("financial", "Submitted grant changes", "important"),
    "finance.grant_update": ("financial", "Submitted grant update", "important"),
    "finance.grant_delete": ("financial", "Submitted grant deletion", "critical"),
    "finance.grant_view": ("financial", "Submitted grant utilization", "important"),
    "finance.approve_grant_utilization": ("approvals", "Submitted grant approval", "important"),
    "finance.reject_grant_utilization": ("approvals", "Submitted grant rejection", "important"),
    "business.income_expenditure": ("financial", "Submitted income and expenditure", "important"),
    "business.stock_register": ("financial", "Submitted stock register changes", "important"),
    "business.stock_movement": ("financial", "Submitted stock movement", "important"),
    "business.business_plan": ("operations", "Submitted business plan changes", "important"),
    "business.monthly_business": ("reports", "Submitted monthly business report", "important"),
    "reports.decide_change": ("approvals", "Decided change request", "important"),
    "reports.generate_mpr_pg": ("reports", "Requested PG MPR generation", "important"),
    "reports.gradation": ("reports", "Submitted PG gradation", "important"),
    "reports.period_lock": ("security", "Submitted period lock change", "critical"),
    "reports.submit_monthly": ("reports", "Submitted monthly report", "important"),
    "reports.approve_monthly": ("approvals", "Submitted monthly approval", "important"),
    "reports.reject_monthly": ("approvals", "Submitted monthly rejection", "important"),
}

REPORT_EXPORT_ENDPOINTS = {
    "reports.export_members_csv", "reports.export_cashbook_csv",
    "reports.export_loans_csv", "reports.export_turnover_csv",
    "reports.export_scope_csv", "reports.reports_hub_export",
}

EXCLUDED = {
    "auth.login", "auth.logout", "auth.login_support", "auth.register_cadre_cc",
    "auth.super_admin_user_edit", "auth.super_admin_password_reset",
}

# Only identity-safe URL parameters; never record headers, request bodies,
# query strings, cookies or uploaded file names.
SAFE_PARAMS = frozenset({
    "pg_id", "user_id", "loan_id", "grant_id", "util_id", "request_id",
    "form_type", "year", "month", "module", "level", "scope", "ref_id",
    "name", "record_id", "member_id", "id",
})


def safe_value(value, key="", depth=0):
    """Bounded, recursive, deny-list scrubber for historic audit documents."""
    if SENSITIVE.search(str(key)):
        return "[REDACTED]"
    if depth > 3:
        return "[COMPLEX VALUE]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, (datetime, ObjectId)):
        return str(value)
    if isinstance(value, str):
        return value[:180] + ("…" if len(value) > 180 else "")
    if isinstance(value, (list, tuple)):
        return [safe_value(item, key, depth + 1) for item in value[:12]]
    if isinstance(value, dict):
        return {str(k)[:70]: safe_value(v, k, depth + 1) for k, v in list(value.items())[:35]}
    return "[VALUE OMITTED]"


def safe_changes(before, after, limit=7):
    """Surface only changed scalar fields; omit PII content and noisy system IDs."""
    if not isinstance(before, dict) or not isinstance(after, dict):
        return []
    ignored = {"_id", "updated_at", "created_at", "ts", "timestamp", "password_reset_at"}
    changes = []
    for key in sorted(set(before) | set(after)):
        if key in ignored or before.get(key) == after.get(key):
            continue
        if len(changes) >= limit:
            break
        value1, value2 = before.get(key), after.get(key)
        if SENSITIVE.search(key):
            # Presence of the change, not the confidential values.
            changes.append({"field": key[:70], "before": "[REDACTED]", "after": "[REDACTED]"})
        elif all(isinstance(v, (str, int, float, bool, type(None), ObjectId)) for v in (value1, value2)):
            changes.append({"field": key[:70], "before": safe_value(value1), "after": safe_value(value2)})
    return changes


def scrub_changes(changes):
    """Never persist before/after values of a sensitive named field."""
    result = []
    for change in (changes or [])[:7]:
        if not isinstance(change, dict):
            continue
        field = str(change.get("field") or "")[:70]
        sensitive = bool(SENSITIVE.search(field))
        result.append({
            "field": field,
            "before": "[REDACTED]" if sensitive else safe_value(change.get("before")),
            "after": "[REDACTED]" if sensitive else safe_value(change.get("after")),
        })
    return result


def _actor_from_request(db):
    user_id = session.get("user_id")
    if not user_id:
        from app.rbac import _authenticate_request
        if _authenticate_request():
            user_id = getattr(g, "user_id", None)
    if not user_id or not ObjectId.is_valid(str(user_id)):
        return None
    # Always trust the persisted identity and role, not user-supplied inputs.
    return db.users.find_one({"_id": ObjectId(str(user_id)), "status": {"$nin": ["disabled", "rejected"]}},
                             {"_id": 1, "username": 1, "full_name": 1, "name": 1, "role": 1,
                              "state_id": 1, "district_id": 1, "block_id": 1, "status": 1})


def _event_ip():
    if not has_request_context():
        return None
    # request.remote_addr is not X-Forwarded-For (which clients can spoof).
    return (request.remote_addr or "")[:64]


def record_event(db, *, action, title, category="operations", severity="important",
                 actor=None, entity=None, entity_id=None, changes=None, detail=None,
                 mark_explicit=True, count=1):
    """Record one safe event; actor is a database user document if supplied."""
    if has_request_context() and mark_explicit:
        g._pgmis_activity_explicit = True
    actor = actor or _actor_from_request(db)
    if not actor or not actor.get("_id"):
        return None
    if category not in CATEGORIES or severity not in {"normal", "important", "critical"}:
        raise ValueError("Invalid audit event category or severity")
    entry = {
        "ts": datetime.utcnow(),
        "actor_id": str(actor["_id"]),
        "actor_name": str(actor.get("full_name") or actor.get("name") or actor.get("username") or "User")[:120],
        "actor_username": str(actor.get("username") or "")[:100],
        "actor_role": str(actor.get("role") or "")[:40],
        "actor_state_id": str(actor.get("state_id") or ""),
        "actor_district_id": str(actor.get("district_id") or ""),
        "actor_block_id": str(actor.get("block_id") or ""),
        "action": str(action)[:90],
        "title": str(title)[:140],
        "category": category,
        "severity": severity,
        "entity": str(entity or "")[:65],
        "entity_id": str(entity_id or "")[:110],
        "detail": str(detail or "")[:220],
        "changes": scrub_changes(changes),
        "result": "Recorded",
        "ip": _event_ip(),
        "count": max(1, int(count)),
    }
    db.activity_events.insert_one(entry)
    return entry


def record_failed_login(db, actor):
    """Record only failed logins for existing accounts; no submitted passwords.

    A 5th failure within 15 minutes is a critical event, earlier failures normal.
    Unknown usernames aren't stored (avoids logging attacker-controlled inputs).
    """
    if not actor:
        return
    now = datetime.utcnow()
    n = db.activity_events.count_documents({
        "actor_id": str(actor["_id"]), "action": "login_failed",
        "ts": {"$gte": now - timedelta(minutes=15)},
    })
    record_event(db, action="login_failed", title="Repeated login failures" if n >= 4 else "Failed login attempt",
                 category="security", severity="critical" if n >= 4 else "normal",
                 actor=actor, detail="Authentication unsuccessful", mark_explicit=False)


def capture_after_request(response):
    """Record relevant authenticated writes after the route completes.

    Legacy route-level audit writes suppress duplicate request events. Form
    validation failures that flash danger/warning are excluded. No GET traffic.
    """
    try:
        endpoint = request.endpoint or ""
        is_export = (request.method == "GET" and endpoint in REPORT_EXPORT_ENDPOINTS)
        if request.method not in ("POST", "PUT", "PATCH", "DELETE") and not is_export:
            return response
        if getattr(g, "_pgmis_activity_explicit", False) or getattr(g, "_pgmis_legacy_audit", False):
            return response
        if endpoint in EXCLUDED or (endpoint not in ROUTES and not is_export):
            return response
        if response.status_code < 200 or response.status_code >= 400:
            return response
        if is_export and "attachment" not in response.headers.get("Content-Disposition", "").lower():
            return response
        old_flash_count = getattr(g, "_pgmis_flash_count", 0)
        flashed = session.get("_flashes") or []
        # A Jinja template may have consumed flash messages already. Flask
        # 3.x retains the flash list on its request context for that request.
        # Inspect it without calling get_flashed_messages() (which would pop
        # messages from redirect responses and change existing behavior).
        try:
            from flask.ctx import _cv_request
            ctx = _cv_request.get(None)
            if ctx is not None and getattr(ctx, "flashes", None) is not None:
                flashed = ctx.flashes
        except (ImportError, AttributeError):
            pass
        if any(cat in {"danger", "error", "warning"} for cat, _ in flashed[old_flash_count:]):
            return response
        if response.is_json and (response.content_length is None or response.content_length < 65536):
            data = response.get_json(silent=True)
            if isinstance(data, dict) and (data.get("error") or data.get("success") is False):
                return response
        cat, title, severity = ("reports", "Exported report data", "important") if is_export else ROUTES[endpoint]
        db = current_app.mongo_db
        params = {k: v for k, v in (request.view_args or {}).items() if k in SAFE_PARAMS}
        # One target identifier; record IDs from the route, not untrusted forms.
        entity_id = next((str(params[k]) for k in ("user_id", "pg_id", "loan_id", "grant_id", "util_id", "request_id", "ref_id", "record_id", "member_id", "id") if k in params), None)
        action = endpoint.split(".", 1)[-1]
        # Administrative delete and authorization actions remain prominent.
        if request.method == "DELETE" or "delete" in action:
            title, severity = "Submitted deletion in " + CATEGORIES[cat], "critical"
        record_event(db, action=action, title=title, category=cat, severity=severity,
                     entity=endpoint.split(".")[0], entity_id=entity_id,
                     detail=" | ".join(f"{k}: {str(v)[:50]}" for k, v in params.items())[:180],
                     mark_explicit=False)
    except Exception:
        # Audit failures must be visible to operators; do not turn an already
        # completed PG MIS workflow into a confusing 500 or retry duplication.
        current_app.logger.exception("Activity event recording failed")
    return response


def initialize_capture(app):
    @app.before_request
    def activity_prepare():
        g._pgmis_flash_count = len(session.get("_flashes", []))

    app.after_request(capture_after_request)


def legacy_normalize(event):
    action = str(event.get("action") or "change").replace(":", " ").replace("_", " ")
    coll = str(event.get("collection") or "record")
    lowered = action.lower()
    severity = "critical" if any(x in lowered for x in ("delete", "password", "disabled", "bank")) else "important"
    if "reject" in lowered or "approv" in lowered or "authorization" in lowered:
        cat = "approvals"
    elif any(x in coll.lower() for x in ("loan", "cash", "grant", "fund", "ledger", "stock", "income")):
        cat = "financial"
    elif "mpr" in coll.lower() or "monthly" in coll.lower():
        cat = "reports"
    elif "document" in coll.lower():
        cat = "documents"
    else:
        cat = "registrations"
    actor = event.get("user") or {}
    return {
        "_id": str(event.get("_id")), "ts": event.get("ts"),
        "actor_id": str(actor.get("user_id") or ""),
        "actor_name": str(actor.get("username") or "Unknown user")[:120],
        "actor_role": str(actor.get("role") or "")[:50],
        "title": " ".join(action.split()).capitalize(),
        "action": event.get("action") or "change", "category": cat,
        "severity": severity, "entity": coll, "entity_id": str(event.get("doc_id") or ""),
        "detail": f"{coll.replace('_', ' ').title()} record",
        "changes": safe_changes(event.get("before"), event.get("after")),
        "result": "Recorded", "ip": None, "source": "legacy", "count": 1,
    }


def new_normalize(event):
    return {
        "_id": str(event.get("_id")), "ts": event.get("ts"),
        "actor_id": event.get("actor_id") or "",
        "actor_name": event.get("actor_name") or "User",
        "actor_role": event.get("actor_role") or "",
        "title": event.get("title") or "Activity",
        "action": event.get("action") or "", "category": event.get("category") or "operations",
        "severity": event.get("severity") or "important",
        "entity": event.get("entity") or "", "entity_id": event.get("entity_id") or "",
        "detail": event.get("detail") or "",
        "changes": scrub_changes(event.get("changes")),
        "result": "Recorded", "ip": event.get("ip"), "source": "activity", "count": event.get("count", 1),
    }
