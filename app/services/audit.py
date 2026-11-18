from datetime import datetime
from bson import ObjectId
from flask import g, has_request_context
from .activity_log import safe_value

def log_audit(db, *, action: str, collection: str, doc_id, user, before=None, after=None, meta=None):
    """Write an audit log entry.

    user: dict with keys user_id, username, role (strings)
    doc_id: ObjectId or str
    """
    meta = meta or {}
    if isinstance(doc_id, ObjectId):
        doc_id_str = str(doc_id)
    else:
        doc_id_str = str(doc_id)

    entry = {
        "ts": datetime.utcnow(),
        "action": action,
        "collection": collection,
        "doc_id": doc_id_str,
        "user": {
            "user_id": str(user.get("user_id")) if user else None,
            "username": user.get("username") if user else None,
            "role": user.get("role") if user else None,
        },
        "before": safe_value(before),
        "after": safe_value(after),
        "meta": safe_value(meta),
    }
    db.audit_logs.insert_one(entry)
    if has_request_context():
        g._pgmis_legacy_audit = True
    return entry
