"""Auditable, scoped, read-only Activity Log for PG MIS administrators."""
import io
import re
from datetime import date, datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo

from bson import ObjectId
from flask import Blueprint, abort, current_app, request, render_template, send_file, session
from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill

from app.constants import ROLE_LABELS
from app.permissions import P_AUDIT_VIEW
from app.rbac import roles_required, permissions_required
from app.services.activity_log import CATEGORIES, legacy_normalize, new_normalize

activity_bp = Blueprint("activity", __name__)
IST = ZoneInfo("Asia/Kolkata")


@activity_bp.after_request
def prevent_activity_caching(response):
    # Prevent browser/proxy caches storing privileged audit and export pages.
    response.headers["Cache-Control"] = "private, no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    return response


PAGE_SIZE = 25
MAX_PAGE = 80
EXPORT_LIMIT = 5000
MANAGED_ROLES = (
    "SUPER_ADMIN", "ADMIN", "DISTRICT_ADMIN", "BLOCK_ADMIN",
    "CLF_ADMIN", "CLF_MANAGER", "PG_DATA_ENTRY", "CADRE_CC",
    "CRCTA", "ANS", "CRCITARD", "VALIDATOR", "VIEWER",
)
ROLE_LABELS_ACTIVITY = {**ROLE_LABELS, "CRCTA": "CRCTA", "ANS": "ANS", "CRCITARD": "CRCITARD"}


def _arguments():
    tab = request.args.get("tab", "all")
    if tab not in {"all", "users", "critical"}:
        tab = "all"
    role = request.args.get("role", "").strip().upper()
    if role not in MANAGED_ROLES:
        role = ""
    category = request.args.get("category", "").strip()
    if category not in CATEGORIES:
        category = ""
    status = request.args.get("status", "").strip().lower()
    if status not in {"active", "disabled", "pending", "rejected"}:
        status = ""
    period = request.args.get("period", "30d").strip()
    if period not in {"today", "yesterday", "7d", "30d", "all", "custom"}:
        period = "30d"
    page = min(MAX_PAGE, max(1, int(request.args.get("page", "1")))) if request.args.get("page", "1").isdigit() else 1
    history_page = min(MAX_PAGE, max(1, int(request.args.get("history_page", "1")))) if request.args.get("history_page", "1").isdigit() else 1
    return {
        "tab": tab, "role": role, "category": category, "status": status,
        "district": request.args.get("district", "")[:60],
        "block": request.args.get("block", "")[:60],
        "search": request.args.get("search", "").strip()[:75],
        "period": period, "from": request.args.get("from", "")[:10],
        "to": request.args.get("to", "")[:10], "page": page, "history_page": history_page,
        "user_id": request.args.get("user_id", "")[:40],
    }


def _date_filter(filters):
    now = datetime.now(IST)
    today = now.date()
    period = filters["period"]
    start, end = None, None
    if period == "today":
        start, end = today, today
    elif period == "yesterday":
        start = end = today - timedelta(days=1)
    elif period == "7d":
        start, end = today - timedelta(days=6), today
    elif period == "30d":
        start, end = today - timedelta(days=29), today
    elif period == "custom":
        try:
            start = date.fromisoformat(filters["from"]) if filters["from"] else None
            end = date.fromisoformat(filters["to"]) if filters["to"] else None
        except ValueError:
            abort(400, "Invalid date filter")
        if start and end and start > end:
            abort(400, "Start date must not exceed end date")
    condition = {}
    if start:
        condition["$gte"] = datetime.combine(start, time.min, IST).astimezone(timezone.utc).replace(tzinfo=None)
    if end:
        condition["$lt"] = datetime.combine(end + timedelta(days=1), time.min, IST).astimezone(timezone.utc).replace(tzinfo=None)
    return condition


def _scoped_users(db):
    """Scope from persisted Admin state, not from request/session location IDs.

    This intentionally matches the existing password-management policy. A State
    Admin can inspect subordinate roles in their own state, plus themselves.
    """
    # The Activity Log is an administrator *web-session* feature. Reject API
    # bearer-token requests rather than inferring scope from a missing session.
    if session.get("role") not in ("SUPER_ADMIN", "ADMIN") or not session.get("user_id"):
        abort(403)
    if not ObjectId.is_valid(str(session["user_id"])):
        abort(403)
    actor = db.users.find_one({"_id": ObjectId(str(session["user_id"]))}, {"role": 1, "status": 1})
    if (not actor or actor.get("role") != session.get("role") or
            (actor.get("status") or "active").lower() != "active"):
        abort(403)
    if session.get("role") == "SUPER_ADMIN":
        match = {}
    else:
        # Reuse the audited state/role boundary in the existing application.
        from app.auth.routes import _user_password_management_scope
        match = _user_password_management_scope(db)
        admin_oid = ObjectId(session["user_id"])
        match = {"$or": [match, {"_id": admin_oid, "role": "ADMIN"}]}
    return list(db.users.find(match, {
        "username": 1, "full_name": 1, "name": 1, "role": 1, "status": 1,
        "state_id": 1, "district_id": 1, "block_id": 1, "last_login": 1,
    }))


def _filter_users(users, filters):
    role = filters["role"]
    district = filters["district"]
    block = filters["block"]
    status = filters["status"]
    term = filters["search"].casefold()
    result = []
    for u in users:
        if role and u.get("role") != role:
            continue
        if district and str(u.get("district_id") or "") != district:
            continue
        if block and str(u.get("block_id") or "") != block:
            continue
        if status and (u.get("status") or "active").lower() != status:
            continue
        if filters["tab"] == "users" and term:
            searchable = " ".join(str(u.get(k) or "") for k in ("username", "name", "full_name", "role"))
            if term not in searchable.casefold():
                continue
        result.append(u)
    return result


def _geo_options(db, users):
    options = []
    for field, collection in (("district_id", "districts"), ("block_id", "blocks")):
        ids = sorted({str(u.get(field)) for u in users if u.get(field)})
        lookup = [ObjectId(x) for x in ids if ObjectId.is_valid(x)] + ids
        names = {}
        if lookup:
            for doc in db[collection].find({"_id": {"$in": lookup}}, {"name": 1}):
                names[str(doc["_id"])] = str(doc.get("name") or "")
        options.append(sorted([{"id": x, "name": names.get(x) or x} for x in ids], key=lambda x: x["name"].lower()))
    return options


def _and(*terms):
    applicable = [x for x in terms if x]
    if not applicable:
        return {}
    return applicable[0] if len(applicable) == 1 else {"$and": applicable}


def _event_queries(filters, actor_ids, *, specific_user=None):
    # None means all user IDs for Superadmin; an empty list for Admin means none.
    allow_new = {"actor_id": {"$in": actor_ids}} if actor_ids is not None else {}
    allow_old = {"user.user_id": {"$in": actor_ids}} if actor_ids is not None else {}
    dates = _date_filter(filters)
    new_date = {"ts": dates} if dates else {}
    old_date = new_date.copy()
    actor_new = {"actor_id": specific_user} if specific_user else {}
    actor_old = {"user.user_id": specific_user} if specific_user else {}
    category = filters["category"]
    new_cat = {"category": category} if category else {}
    legacy_cat_patterns = {
        "authentication": {"_id": {"$exists": False}},
        "users": {"collection": "users"},
        "security": {"action": {"$regex": "password|disabled|login|lock", "$options": "i"}},
        "approvals": {"action": {"$regex": "approv|reject|authorization|apply", "$options": "i"}},
        "financial": {"collection": {"$regex": "loan|cash|grant|stock|fund|ledger|income|finance", "$options": "i"}},
        "registrations": {"collection": {"$regex": "pgs|members|registration|change_request", "$options": "i"}},
        "reports": {"collection": {"$regex": "mpr|month|report", "$options": "i"}},
        "documents": {"collection": {"$regex": "document", "$options": "i"}},
        "mapping": {"collection": {"$regex": "states|districts|blocks|clfs|mapping", "$options": "i"}},
        "operations": {"collection": {"$regex": "meeting|crop|plan|register", "$options": "i"}},
    }
    old_cat = legacy_cat_patterns[category] if category else {}
    critical_new = {"severity": "critical"} if filters["tab"] == "critical" else {}
    critical_old = {"action": {"$regex": "delete|password|disabled|bank", "$options": "i"}} if filters["tab"] == "critical" else {}
    search = filters["search"] if filters["tab"] != "users" and not specific_user else ""
    rx = {"$regex": re.escape(search), "$options": "i"}
    new_search = {"$or": [{k: rx} for k in ("actor_name", "actor_username", "title", "entity_id", "action")]} if search else {}
    old_search = {"$or": [{k: rx} for k in ("user.username", "action", "collection", "doc_id")]} if search else {}
    return (
        _and(allow_new, new_date, actor_new, new_cat, critical_new, new_search),
        _and(allow_old, old_date, actor_old, old_cat, critical_old, old_search),
    )


def _merge_logs(db, new_query, old_query, *, page=1, page_size=PAGE_SIZE):
    """Merge two indexed streams; bounded upper limit prevents unbounded reads."""
    end = page * page_size
    new = [new_normalize(x) for x in db.activity_events.find(new_query).sort("ts", -1).limit(end)]
    old = [legacy_normalize(x) for x in db.audit_logs.find(old_query).sort("ts", -1).limit(end)]
    combined = new + old
    combined.sort(key=lambda x: x.get("ts") or datetime.min, reverse=True)
    return combined[(page - 1) * page_size:end]


def _counts(db, queries):
    return db.activity_events.count_documents(queries[0]) + db.audit_logs.count_documents(queries[1])


def _query_url(filters, endpoint="activity.dashboard", **updates):
    from flask import url_for
    from urllib.parse import urlencode
    data = {k: str(v) for k, v in filters.items() if v and k != "page" and k != "user_id"}
    data.update({k: str(v) for k, v in updates.items() if v is not None})
    data = {k: v for k, v in data.items() if v != ""}
    return url_for(endpoint) + "?" + urlencode(data)


def _page_payload(db, filters, users):
    user_filter = _filter_users(users, filters)
    ids = [str(x["_id"]) for x in user_filter]
    # Superadmin sees historical activity by deleted users when no user filter is
    # active. Admin never gets this bypass.
    unrestricted = (session.get("role") == "SUPER_ADMIN" and not any(filters[k] for k in ("role", "district", "block", "status")))
    actor_ids = None if unrestricted else ids
    queries = _event_queries(filters, actor_ids)
    total = _counts(db, queries)
    items = _merge_logs(db, *queries, page=filters["page"])
    activity_pages = min(MAX_PAGE, max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE))
    count_critical_filters = {**filters, "tab": "critical", "search": "", "category": ""}
    critical_queries = _event_queries(count_critical_filters, actor_ids)
    critical_count = _counts(db, critical_queries)
    return items, total, activity_pages, critical_count, actor_ids


def _format_users(rows, db, period_filters):
    result = []
    for u in rows:
        user_id = str(u["_id"])
        q = _event_queries({**period_filters, "tab": "users", "category": "", "search": ""}, [user_id], specific_user=user_id)
        result.append({
            "id": user_id,
            "name": (u.get("full_name") or u.get("name") or u.get("username") or "User")[:120],
            "username": u.get("username") or "",
            "role": u.get("role") or "",
            "role_label": ROLE_LABELS_ACTIVITY.get(u.get("role"), u.get("role") or ""),
            "district": str(u.get("district_id") or ""),
            "block": str(u.get("block_id") or ""),
            "status": (u.get("status") or "active").lower(),
            "last_login": u.get("last_login"),
            "actions": _counts(db, q),
        })
    return result


@activity_bp.route("/", methods=["GET"])
@roles_required("SUPER_ADMIN", "ADMIN")
@permissions_required(P_AUDIT_VIEW)
def dashboard():
    db = current_app.mongo_db
    filters = _arguments()
    scoped = _scoped_users(db)
    selected = None
    selected_total, history_pages = 0, 1
    if filters["tab"] == "users":
        filtered = _filter_users(scoped, filters)
        total_users = len(filtered)
        start = (filters["page"] - 1) * PAGE_SIZE
        page_users = _format_users(filtered[start:start + PAGE_SIZE], db, filters)
        user_pages = min(MAX_PAGE, max(1, (total_users + PAGE_SIZE - 1) // PAGE_SIZE))
        user_id = filters["user_id"]
        selected_items = []
        if user_id:
            selected = next((u for u in filtered if str(u["_id"]) == user_id), None)
            if selected is None:
                abort(404)
            sq = _event_queries({**filters, "search": "", "category": ""}, [user_id], specific_user=user_id)
            selected_total = _counts(db, sq)
            history_pages = min(MAX_PAGE, max(1, (selected_total + 29) // 30))
            selected_items = _merge_logs(db, *sq, page=filters["history_page"], page_size=30)
        items, total, pages, critical_count = [], 0, user_pages, 0
    else:
        items, total, pages, critical_count, _ = _page_payload(db, filters, scoped)
        page_users, selected_items, total_users = [], [], 0
    district_options, block_options = _geo_options(db, scoped)
    login_range = _date_filter(filters)
    def logged_in_range(u):
        last = u.get("last_login")
        if not isinstance(last, datetime):
            return False
        if last.tzinfo is not None:
            last = last.astimezone(timezone.utc).replace(tzinfo=None)
        return (not login_range.get("$gte") or last >= login_range["$gte"]) and \
               (not login_range.get("$lt") or last < login_range["$lt"])
    active_login_count = sum(1 for user in scoped if logged_in_range(user))

    def ist_time(value):
        if not isinstance(value, datetime):
            return "Not recorded"
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(IST).strftime("%d %b %Y, %I:%M %p IST")

    return render_template(
        "activity_log.html", ist_time=ist_time, filters=filters,
        active_login_count=active_login_count, events=items, users=page_users,
        selected=selected, selected_events=selected_items,
        selected_total=selected_total, history_pages=history_pages,
        current_count=total_users if filters["tab"] == "users" else total,
        critical_count=critical_count,
        user_count=len(_filter_users(scoped, {**filters, "tab": "users", "search": ""})),
        page_count=pages, page=filters["page"],
        categories=CATEGORIES, role_labels=ROLE_LABELS_ACTIVITY,
        district_options=district_options, block_options=block_options,
        query_url=lambda **kwargs: _query_url(filters, **kwargs),
        export_url=lambda: _query_url(filters, endpoint="activity.export"),
    )


def _excel_text(value):
    """Prevent formula injection into downloaded spreadsheets."""
    if isinstance(value, datetime):
        value = value.replace(tzinfo=timezone.utc).astimezone(IST).strftime("%d %b %Y, %I:%M %p IST")
    raw = str(value or "")[:400]
    return "'" + raw if raw.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else raw


@activity_bp.route("/export", methods=["GET"])
@roles_required("SUPER_ADMIN", "ADMIN")
@permissions_required(P_AUDIT_VIEW)
def export():
    db = current_app.mongo_db
    filters = _arguments()
    users = _scoped_users(db)
    filtered_users = _filter_users(users, filters)
    unrestricted = session.get("role") == "SUPER_ADMIN" and not any(filters[k] for k in ("role", "district", "block", "status"))
    ids = None if unrestricted else [str(u["_id"]) for u in filtered_users]
    if filters["user_id"]:
        if filters["user_id"] not in {str(x["_id"]) for x in filtered_users}:
            abort(404)
        user_id = filters["user_id"]
    else:
        user_id = None
    query = _event_queries(filters, ids, specific_user=user_id)
    if _counts(db, query) > EXPORT_LIMIT:
        abort(413, "Please narrow the filters: export supports up to 5,000 records")
    rows = _merge_logs(db, *query, page=1, page_size=EXPORT_LIMIT)
    wb = Workbook()
    ws = wb.active
    ws.title = "PG MIS Activity"
    headings = ["Date (IST)", "User", "Role", "Activity", "Category", "Priority", "Module", "Record ID", "Change details", "Source IP"]
    ws.append(headings)
    for cell in ws[1]:
        cell.fill = PatternFill("solid", fgColor="0B4D3A")
        cell.font = Font(color="FFFFFF", bold=True)
        cell.alignment = Alignment(wrap_text=True)
    for row in rows:
        changes = "; ".join(f"{c['field']}: {c['before']} → {c['after']}" for c in row.get("changes", []))
        ws.append([_excel_text(row.get(k)) for k in ("ts", "actor_name", "actor_role", "title", "category", "severity", "entity", "entity_id")]
                  + [_excel_text(changes), _excel_text(row.get("ip"))])
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions
    for letter, width in {"A": 26, "B": 27, "C": 22, "D": 42, "E": 25, "F": 15, "G": 25, "H": 29, "I": 65, "J": 23}.items():
        ws.column_dimensions[letter].width = width
    buffer = io.BytesIO()
    wb.save(buffer)
    buffer.seek(0)
    response = send_file(buffer, as_attachment=True, download_name="PGMIS_Activity_Log.xlsx",
                         mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    try:
        from app.services.activity_log import record_event
        record_event(db, action="activity_export", title="Exported activity log",
                     category="security", severity="important", detail="Filtered Excel export")
    except Exception:
        current_app.logger.exception("Activity export auditing failed")
    return response


def user_preview(db, user_id, limit=8):
    """Caller MUST already authorize target user using the existing scope."""
    filters = {"tab": "users", "role": "", "district": "", "block": "", "status": "",
               "search": "", "period": "all", "from": "", "to": "", "category": ""}
    query = _event_queries(filters, [str(user_id)], specific_user=str(user_id))
    return _merge_logs(db, *query, page=1, page_size=limit)
