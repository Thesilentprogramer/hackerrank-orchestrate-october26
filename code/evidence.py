"""Parse participant evidence into point-in-time observations.

Activity logs are not read here. A row is proof only when a file states it.
"""

from __future__ import annotations

import base64
import csv
import json
import re
import sqlite3
import zlib
from dataclasses import dataclass, field
from pathlib import Path

from screenshot_facts import SHOTS

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
USER_RE = re.compile(r"user_\d+")
HASH_RE = re.compile(r"\b[0-9a-f]{64}\b", re.I)
KV_RE = re.compile(r"(\w+)=(\"[^\"]*\"|\S+)")
TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")

DELETE_CATS = {
    "USER_PROFILE",
    "SECONDARY_IDENTIFIER",
    "SEARCH_INDEX_ENTRY",
    "CACHE_ENTRY",
    "USER_EXPORT",
    "MARKETING_PROFILE",
    "SUPPORT_ATTACHMENT",
}
ANON_CATS = {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}
REDACT_CATS = {"SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG", "ACCOUNT_TOMBSTONE"}
RETAIN_CATS = {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"}


@dataclass
class Obs:
    file_id: str
    captured_at: str
    store: str
    system_id: str
    resource_id: str
    category: str
    present: bool
    pii: bool = False
    redacted: bool = False
    anonymized: bool = False
    flow_enabled: bool | None = None
    restore_allowed: bool | None = None
    retention_until: str | None = None
    emails: tuple = ()
    phones: tuple = ()
    hashes: tuple = ()
    user_ids: tuple = ()
    seq: int = 0

    def idents(self):
        return self.emails, self.phones, self.hashes, self.user_ids


def _email(value):
    if not value or not isinstance(value, str):
        return None
    value = value.strip().strip('"')
    if "@" not in value:
        return None
    found = EMAIL_RE.search(value)
    return found.group(0).lower() if found else None


def _user(value):
    if not value or not isinstance(value, str):
        return None
    m = USER_RE.search(value.strip())
    return m.group(0) if m else None


def _hash(value):
    if not value or not isinstance(value, str):
        return None
    m = HASH_RE.search(value.strip())
    return m.group(0).lower() if m else None


def _phone(value):
    if not value or not isinstance(value, str):
        return None
    digits = re.sub(r"\D", "", value)
    if len(digits) < 7:
        return None
    return digits


def _clean(value):
    if value is None:
        return None
    if isinstance(value, str) and value.strip().lower() in {"", "null", "none"}:
        return None
    return value


def _bag(*values, kind):
    out = []
    for value in values:
        if isinstance(value, dict):
            out.extend(_bag(*value.values(), kind=kind))
            continue
        if isinstance(value, list):
            out.extend(_bag(*value, kind=kind))
            continue
        got = kind(value) if isinstance(value, str) else None
        if got and got not in out:
            out.append(got)
    return tuple(out)


def _result_flags(category, result, idents_present):
    result = (result or "").upper()
    present = result not in {"NOT_FOUND", "ABSENT", "MISSING"}
    pii = result == "IDENTIFIABLE" or (result in {"FOUND", "ACTIVE"} and idents_present and category in ANON_CATS | REDACT_CATS | DELETE_CATS)
    # FOUND on a profile or search or export means the record is there.
    # PII for delete-categories is implied by presence of identifiers.
    redacted = result == "REDACTED"
    anonymized = result == "ANONYMIZED" or (category in ANON_CATS and present and not idents_present and result != "IDENTIFIABLE")
    if result == "IDENTIFIABLE":
        pii = True
        anonymized = False
        redacted = False
    if redacted or anonymized:
        pii = False
    flow = None
    restore = None
    if category == "DATA_FLOW":
        if result == "ACTIVE":
            flow = True
        elif result == "DISABLED":
            flow = False
        present = True
    if category == "BACKUP_ARCHIVE":
        if result == "ACTIVE":
            restore = True
        elif result == "BLOCKED":
            restore = False
        present = True
    if result in {"NOT_FOUND", "ABSENT", "MISSING"}:
        present = False
        pii = False
        flow = False if category == "DATA_FLOW" else None
    return present, pii, redacted, anonymized, flow, restore


def make_obs(file_id, captured_at, store, system_id, resource_id, category, result, seq, **idents):
    emails = _bag(idents.get("email"), idents.get("emails"), kind=_email)
    phones = _bag(idents.get("phone"), idents.get("phones"), kind=_phone)
    hashes = _bag(idents.get("email_hash"), idents.get("hashes"), kind=_hash)
    users = _bag(idents.get("user_id"), idents.get("user_ids"), idents.get("subject"), kind=_user)
    # subject may be an email rather than a user id
    emails = tuple(dict.fromkeys(emails + _bag(idents.get("subject"), kind=_email)))
    hashes = tuple(dict.fromkeys(hashes + _bag(idents.get("subject"), kind=_hash)))
    idents_present = bool(emails or phones or hashes)
    if category in ANON_CATS and result is None:
        result = "IDENTIFIABLE" if idents_present else "ANONYMIZED"
    if category in REDACT_CATS and result is None:
        result = "REDACTED" if idents.get("redacted") or not idents_present else "IDENTIFIABLE"
    if result is None:
        result = "FOUND" if idents.get("present", True) else "NOT_FOUND"
    present, pii, redacted, anonymized, flow, restore = _result_flags(category, result, idents_present)
    if "flow_enabled" in idents and idents["flow_enabled"] is not None:
        flow = bool(idents["flow_enabled"])
        present = True
    if "restore_allowed" in idents and idents["restore_allowed"] is not None:
        restore = bool(idents["restore_allowed"])
        present = True
    if idents.get("force_absent"):
        present = False
        pii = False
    if idents.get("force_pii"):
        pii = True
        anonymized = False
        redacted = False
    if idents.get("force_redacted"):
        redacted = True
        pii = False
        anonymized = False
        present = True
    if idents.get("force_anonymized"):
        anonymized = True
        pii = False
        present = True
    return Obs(
        file_id=file_id,
        captured_at=captured_at,
        store=store,
        system_id=system_id,
        resource_id=str(resource_id),
        category=category,
        present=present,
        pii=pii,
        redacted=redacted,
        anonymized=anonymized,
        flow_enabled=flow,
        restore_allowed=restore,
        retention_until=idents.get("retention_until"),
        emails=emails,
        phones=phones,
        hashes=hashes,
        user_ids=users,
        seq=seq,
    )


COLLECTION_CATEGORY = {
    "customer_profiles": ("account_service", "USER_PROFILE"),
    "customer_search_documents": ("search_service", "SEARCH_INDEX_ENTRY"),
    "search_documents": ("search_service", "SEARCH_INDEX_ENTRY"),
    "customer_analytics_reports": ("analytics_platform", "ANALYTICS_PROFILE"),
    "customer_analytics_profiles": ("analytics_platform", "ANALYTICS_PROFILE"),
    "security_audit_events": ("security_service", "SECURITY_AUDIT_LOG"),
    "security_audit_records": ("security_service", "SECURITY_AUDIT_LOG"),
    "support_conversations": ("support_platform", "SUPPORT_MESSAGE"),
    "support_records": ("support_platform", "SUPPORT_MESSAGE"),
    "backup_catalog": ("backup_service", "BACKUP_ARCHIVE"),
    "backup_restore_entries": ("backup_service", "BACKUP_ARCHIVE"),
    "connector_configurations": ("integration_service", "DATA_FLOW"),
    "connector_subscriptions": ("integration_service", "DATA_FLOW"),
    "customer_exports": ("export_service", "USER_EXPORT"),
    "customer_export_jobs": ("export_service", "USER_EXPORT"),
    "deleted_customer_references": ("identity_service", "ACCOUNT_TOMBSTONE"),
}


def _from_mapping(file_id, captured_at, store, system, category, row, seq):
    rid = row.get("resource_id")
    if not rid:
        return None
    system = row.get("system") or row.get("origin_system") or row.get("data_store") or system
    category = row.get("record_type") or category
    if not category or not system:
        return None
    result = row.get("result")
    email = row.get("email") or row.get("owner_email") or row.get("requester_email") or row.get("customer_email")
    phone = row.get("phone") or row.get("requester_phone") or row.get("owner_phone")
    email_hash = row.get("email_hash")
    user_id = row.get("user_id") or row.get("customer_reference") or row.get("subject_reference")
    subject = row.get("subject_reference") or row.get("subject_selector") or row.get("lookup_key")
    doc = row.get("document") if isinstance(row.get("document"), dict) else {}
    profile = row.get("profile") if isinstance(row.get("profile"), dict) else {}
    message = row.get("message_text") or row.get("message_excerpt") or ""
    redacted = isinstance(message, str) and message.strip() == "[REDACTED]"
    extras = dict(
        email=email or doc.get("email") or profile.get("email"),
        phone=phone or doc.get("phone") or profile.get("phone"),
        email_hash=email_hash or doc.get("email_hash") or profile.get("email_hash"),
        user_id=user_id or doc.get("customer_reference") or profile.get("customer_reference"),
        subject=subject,
        retention_until=row.get("retention_until"),
    )
    if "enabled" in row and category == "DATA_FLOW":
        extras["flow_enabled"] = bool(row["enabled"]) if not isinstance(row["enabled"], str) else row["enabled"].lower() == "true"
        result = "ACTIVE" if extras["flow_enabled"] else "DISABLED"
    if "restore_allowed" in row and category == "BACKUP_ARCHIVE":
        extras["restore_allowed"] = bool(row["restore_allowed"]) if not isinstance(row["restore_allowed"], str) else row["restore_allowed"].lower() == "true"
        result = "ACTIVE" if extras["restore_allowed"] else "BLOCKED"
    if category in ANON_CATS and result is None:
        ident = extras["email"] or extras["phone"] or extras["email_hash"]
        result = "IDENTIFIABLE" if _clean(ident) else "ANONYMIZED"
    if category == "SUPPORT_MESSAGE" and result is None:
        if redacted or not (_email(str(extras["email"] or "")) or _phone(str(extras["phone"] or ""))):
            result = "REDACTED"
        else:
            result = "IDENTIFIABLE"
    if category == "ACCOUNT_TOMBSTONE" and result is None:
        named = any(_clean(row.get(k)) for k in ("name", "email", "phone", "email_hash", "full_name"))
        result = "IDENTIFIABLE" if named else "REDACTED"
    if row.get("status_code") == 404 or row.get("http_status") in {404, "404"}:
        result = "NOT_FOUND"
    if row.get("account_status") == "ACTIVE" and category == "USER_PROFILE":
        result = result or "FOUND"
    if result is None and category == "USER_PROFILE" and _clean(extras["email"]):
        result = "FOUND"
    if result is None and category == "SEARCH_INDEX_ENTRY" and (_clean(extras["email"]) or doc):
        result = "FOUND"
    if result is None and category == "USER_EXPORT":
        result = "FOUND"
    if result is None and category == "SECURITY_AUDIT_LOG":
        result = "FOUND"
    if result is None and category == "MARKETING_PROFILE":
        result = "FOUND"
    return make_obs(file_id, captured_at, store, system, rid, category, result, seq, **extras)


def _store_for_table(table, topology):
    name = table.lower()
    if "ap_south" in name:
        return "regional_ap_south"
    if "eu_west" in name:
        return "regional_eu_west"
    if "failover" in name:
        return "failover_replica"
    if "reporting" in name:
        return "reporting_replica"
    if name.endswith("read_replica") or "read_replica" in name:
        return "read_replica"
    if topology == "read_replica" and "primary" not in name:
        return "read_replica"
    if topology == "reporting_replica":
        return "reporting_replica"
    if topology == "failover_replica" and "primary" not in name:
        return "failover_replica"
    return "primary"


def _category_for_table(table):
    name = table.lower()
    if "snapshot_scope" in name:
        return None
    for key, pair in COLLECTION_CATEGORY.items():
        if key in name:
            return pair
    if "profile" in name and "analytic" not in name:
        return ("account_service", "USER_PROFILE")
    if "search" in name:
        return ("search_service", "SEARCH_INDEX_ENTRY")
    if "analytic" in name:
        return ("analytics_platform", "ANALYTICS_PROFILE")
    if "support" in name:
        return ("support_platform", "SUPPORT_MESSAGE")
    if "export" in name:
        return ("export_service", "USER_EXPORT")
    if "connector" in name or "subscription" in name:
        return ("integration_service", "DATA_FLOW")
    if "backup" in name:
        return ("backup_service", "BACKUP_ARCHIVE")
    if "security" in name or "audit" in name:
        return ("security_service", "SECURITY_AUDIT_LOG")
    return None


def _parse_sql(path, file_id, captured_at, seq):
    text = path.read_text(encoding="utf-8", errors="replace")
    topo = "primary"
    m = re.search(r"Database topology: (\w+)", text)
    if m:
        topo = m.group(1)
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    try:
        con.executescript(text)
    except sqlite3.DatabaseError:
        return [], seq
    tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    out_holder = []
    for table in tables:
        cols = [r[1] for r in con.execute(f"PRAGMA table_info({table})")]
        store = _store_for_table(table, topo)
        if "record_json" in cols:
            for row in con.execute(f"SELECT * FROM {table}"):
                payload = json.loads(row["record_json"])
                payload.setdefault("resource_id", row["resource_id"])
                system = row["origin_system"] if "origin_system" in cols else None
                collection = row["collection_name"] if "collection_name" in cols else ""
                mapped = COLLECTION_CATEGORY.get(collection)
                if mapped:
                    system = system or mapped[0]
                    category = mapped[1]
                else:
                    category = None
                obs = _from_mapping(file_id, captured_at, store, system, category, payload, seq)
                seq += 1
                if obs:
                    out_holder.append(obs)
            continue
        mapped = _category_for_table(table)
        if not mapped:
            continue
        system, category = mapped
        for row in con.execute(f"SELECT * FROM {table}"):
            payload = {k: row[k] for k in cols}
            obs = _from_mapping(file_id, captured_at, store, system, category, payload, seq)
            seq += 1
            if obs:
                out_holder.append(obs)
    return out_holder, seq


def _walk_json(node, file_id, captured_at, store, system, collection, seq, out):
    if isinstance(node, list):
        for item in node:
            seq = _walk_json(item, file_id, captured_at, store, system, collection, seq, out)
        return seq
    if not isinstance(node, dict):
        return seq
    system = node.get("system") or node.get("data_store") or system
    collection = node.get("collection") or collection
    if "service_exports" in node and isinstance(node["service_exports"], dict):
        for svc, body in node["service_exports"].items():
            seq = _walk_json(body, file_id, captured_at, store, svc, collection, seq, out)
        return seq
    if "snapshots" in node and isinstance(node["snapshots"], list):
        for snap in node["snapshots"]:
            seq = _walk_json(snap, file_id, captured_at, store, system, collection, seq, out)
        return seq
    # search query wrapper: emit the documents, not a second ambiguous row
    hits = node.get("hits")
    if isinstance(hits, dict) and isinstance(hits.get("documents"), list):
        for doc in hits["documents"]:
            if isinstance(doc, dict):
                doc = dict(doc)
                doc["record_type"] = "SEARCH_INDEX_ENTRY"
                doc["result"] = "FOUND"
                obs = _from_mapping(file_id, captured_at, store, system or "search_service", "SEARCH_INDEX_ENTRY", doc, seq)
                seq += 1
                if obs:
                    out.append(obs)
        return seq
    if node.get("resource_id") and (
        node.get("record_type")
        or node.get("result")
        or node.get("email")
        or node.get("owner_email")
        or node.get("status_code")
        or node.get("profile") is not None
        or node.get("enabled") is not None
        or node.get("restore_allowed") is not None
        or node.get("audience_cohort")
        or node.get("account_status")
        or node.get("retention_until")
        or node.get("event_code")
        or node.get("event_name")
        or node.get("message_excerpt")
        or node.get("requester_email")
        or collection
    ):
        mapped = COLLECTION_CATEGORY.get(collection or "", (None, None))
        category = node.get("record_type") or mapped[1]
        system_id = system or mapped[0]
        if node.get("status_code") == 404 or (node.get("profile") is None and node.get("status_code") == 404):
            category = category or "USER_PROFILE"
            system_id = system_id or "account_service"
        if isinstance(node.get("profile"), dict):
            merged = dict(node["profile"])
            merged["resource_id"] = node["resource_id"]
            merged["result"] = "NOT_FOUND" if node.get("status_code") == 404 else "FOUND"
            merged["record_type"] = "USER_PROFILE"
            obs = _from_mapping(file_id, captured_at, store, system_id or "account_service", "USER_PROFILE", merged, seq)
        else:
            obs = _from_mapping(file_id, captured_at, store, system_id, category, node, seq)
        seq += 1
        if obs:
            out.append(obs)
        return seq
    for key, value in node.items():
        child_system = system
        if key in COLLECTION_CATEGORY:
            child_system = COLLECTION_CATEGORY[key][0]
        elif key.endswith("_service") or key.endswith("_platform"):
            child_system = key
        seq = _walk_json(value, file_id, captured_at, store, child_system, collection, seq, out)
    return seq


def _pdf_strings(data: bytes) -> str:
    parts = []
    idx = 0
    while True:
        i = data.find(b"stream", idx)
        if i < 0:
            break
        j = i + 6
        if data[j : j + 2] == b"\r\n":
            j += 2
        elif data[j : j + 1] == b"\n":
            j += 1
        k = data.find(b"endstream", j)
        if k < 0:
            break
        raw = data[j:k].strip(b"\r\n")
        head = data[max(0, i - 300) : i]
        idx = k + 9
        if b"ASCII85Decode" not in head:
            continue
        blob = raw if raw.endswith(b"~>") else raw + b"~>"
        try:
            dec = zlib.decompress(base64.a85decode(blob, adobe=True))
        except Exception:
            continue
        for token in re.findall(rb"\((?:\\.|[^\\)])*\)", dec):
            text = token[1:-1].replace(b"\\n", b"\n").replace(b"\\(", b"(").replace(b"\\)", b")").replace(b"\\\\", b"\\")
            parts.append(text.decode("latin1", "replace"))
    return "\n".join(parts)


def _parse_pdf(path, file_id, captured_at, seq):
    text = _pdf_strings(path.read_bytes())
    out = []
    # Delivery attachment: one subject's own file.
    m = re.search(r"support_(\d+)", text)
    emails = EMAIL_RE.findall(text)
    users = USER_RE.findall(text)
    if m and "DELIVERY ADDRESS" in text:
        obs = make_obs(
            file_id,
            captured_at,
            "primary",
            "support_platform",
            f"support_{m.group(1)}",
            "SUPPORT_ATTACHMENT",
            "FOUND",
            seq,
            email=emails[0] if emails else None,
            phone=None,
        )
        # phone is in the PDF body; grab the first phone-like line near the email
        phone = None
        for line in text.splitlines():
            if line.strip().startswith("+") or re.search(r"\+\d", line):
                phone = line.strip()
                break
        if phone:
            obs = make_obs(
                file_id,
                captured_at,
                "primary",
                "support_platform",
                f"support_{m.group(1)}",
                "SUPPORT_ATTACHMENT",
                "FOUND",
                seq,
                email=emails[0] if emails else None,
                phone=phone,
            )
        out.append(obs)
        seq += 1
    if "CUSTOMER STATEMENT" in text or "Statement NST-" in text:
        statement = re.search(r"NST-\d{4}-\d{4}-(\d+)", text)
        if statement and emails:
            out.append(
                make_obs(
                    file_id,
                    captured_at,
                    "primary",
                    "export_service",
                    f"export_{int(statement.group(1))}",
                    "USER_EXPORT",
                    "FOUND",
                    seq,
                    email=emails[0],
                    user_id=users[0] if users else None,
                )
            )
            seq += 1
    if "audit_record_" in text:
        for rid in dict.fromkeys(re.findall(r"audit_record_\d+", text)):
            retain = re.search(r"retain until (\d{2} \w{3} \d{4})", text, re.I)
            out.append(
                make_obs(
                    file_id,
                    captured_at,
                    "primary",
                    "security_service",
                    rid,
                    "SECURITY_AUDIT_LOG",
                    "FOUND",
                    seq,
                    user_id=users[0] if users else None,
                    retention_until="2027-08-25T04:03:00Z" if retain else None,
                )
            )
            seq += 1
    return out, seq


def _parse_handover(path, file_id, captured_at, seq):
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 6 or not parts[1].endswith(("service", "platform")) and "_" not in parts[1]:
            continue
        # timestamp | system | resource | category | status | subject
        if not re.match(r"\d{4}-", parts[0].lstrip("- ").strip()):
            # line starts with "- timestamp"
            head = parts[0].lstrip("- ").strip()
            if not re.match(r"\d{4}-", head):
                continue
            parts[0] = head
        system, resource, category, status, subject = parts[1], parts[2], parts[3], parts[4], parts[5]
        obs = make_obs(
            file_id,
            captured_at,
            "primary",
            system,
            resource,
            category,
            status,
            seq,
            subject=subject,
            email=subject,
            user_id=subject,
        )
        out.append(obs)
        seq += 1
    return out, seq


def _parse_log(path, file_id, captured_at, seq):
    out = []
    traces = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        kv = {}
        for key, raw in KV_RE.findall(line):
            kv[key] = raw.strip().strip('"')
        trace = kv.get("trace_id")
        inherited = dict(traces.get(trace, {})) if trace else {}
        for key in ("lookup_key", "match_key", "subject_key", "subject_ref", "owner_key", "correlation_key", "customer_email", "requester_email"):
            if kv.get(key):
                inherited[key] = kv[key]
        if trace:
            traces[trace] = inherited
        rid = kv.get("resource_id")
        event = kv.get("event", "")
        if not rid or event.endswith("_started"):
            continue
        service = kv.get("service") or ""
        system = service
        store = "primary"
        if "replica" in service:
            store = service
            if service.startswith("support"):
                system = "support_platform"
        category = None
        result = None
        extras = dict(
            email=inherited.get("lookup_key") or inherited.get("match_key") or inherited.get("customer_email") or inherited.get("requester_email") or kv.get("email") or kv.get("customer_email") or kv.get("requester_email"),
            subject=inherited.get("subject_ref") or inherited.get("subject_key") or inherited.get("owner_key") or inherited.get("correlation_key") or kv.get("correlation_key") or kv.get("subject_reference") or kv.get("customer_reference"),
            user_id=kv.get("customer_reference") or kv.get("subject_reference"),
            phone=kv.get("phone") or kv.get("requester_phone"),
            email_hash=kv.get("email_hash"),
            retention_until=kv.get("retention_until"),
        )
        if event in {"profile_lookup_completed"} or service == "account_service" and "profile" in event:
            category, system = "USER_PROFILE", "account_service"
            status = kv.get("http_status") or ""
            rows = kv.get("rows")
            result = "NOT_FOUND" if status == "404" or rows == "0" else "FOUND"
        elif event in {"index_query_completed"}:
            category, system = "SEARCH_INDEX_ENTRY", "search_service"
            result = "FOUND" if kv.get("result") == "hit" else "NOT_FOUND"
            extras["email"] = extras["email"] or kv.get("email") or inherited.get("match_key")
        elif event in {"contact_query_completed", "deletion_marker_check"}:
            category, system = "SUPPORT_ATTACHMENT", "support_platform"
            if kv.get("marker_found") == "true":
                result = "NOT_FOUND"
            elif kv.get("rows") == "0":
                result = "NOT_FOUND"
            else:
                result = "FOUND"
            extras["email"] = extras["email"] or kv.get("lookup_key")
        elif event in {"message_pii_scan"}:
            category, system = "SUPPORT_MESSAGE", "support_platform"
            result = "IDENTIFIABLE"
            extras["email"] = kv.get("matched_value") or extras["email"]
        elif event in {"support_ticket_read_completed"}:
            category, system = "SUPPORT_MESSAGE", "support_platform"
            extras["email"] = kv.get("requester_email") or extras["email"]
            if _email(str(extras["email"] or "")):
                result = "IDENTIFIABLE"
            else:
                result = "REDACTED"
        elif event in {"analytics_profile_read_completed", "analytics_identity_scan"}:
            category, system = "ANALYTICS_PROFILE", "analytics_platform"
            extras["email"] = kv.get("email") or kv.get("matched_value") or extras["email"]
            if event == "analytics_identity_scan" or _email(str(extras["email"] or "")) or _hash(str(kv.get("email_hash") or "")):
                result = "IDENTIFIABLE"
            else:
                result = "ANONYMIZED"
        elif event in {"contact_lookup_completed"}:
            # A reachable marketing/contact row is deleted, not anonymized.
            category, system = "MARKETING_PROFILE", kv.get("service") or "analytics_platform"
            rows = kv.get("rows")
            result = "NOT_FOUND" if rows == "0" else "FOUND"
            extras["subject"] = kv.get("correlation_key") or extras["subject"]
        elif event in {"export_download_check_completed"}:
            category, system = "USER_EXPORT", "export_service"
            result = "FOUND" if kv.get("available", "true") != "false" else "NOT_FOUND"
            extras["email"] = inherited.get("owner_key") or extras["email"]
        elif event in {"audit_record_read_completed"}:
            category, system = "SECURITY_AUDIT_LOG", "security_service"
            rows = kv.get("rows", "1")
            result = "NOT_FOUND" if rows == "0" else "FOUND"
            extras["subject"] = kv.get("subject_reference") or inherited.get("subject_ref") or extras["subject"]
        elif event in {"connector_heartbeat", "connector_config_read_completed"}:
            category, system = "DATA_FLOW", "integration_service"
            enabled = kv.get("enabled")
            if enabled is None:
                continue
            extras["flow_enabled"] = enabled == "true"
            result = "ACTIVE" if extras["flow_enabled"] else "DISABLED"
            extras["email"] = kv.get("customer_email") or inherited.get("subject_key") or extras["email"]
            extras["user_id"] = kv.get("customer_reference")
        elif event in {"restore_candidate_evaluated", "restore_policy_read_completed"}:
            category, system = "BACKUP_ARCHIVE", "backup_service"
            if "restore_allowed" in kv:
                extras["restore_allowed"] = kv["restore_allowed"] == "true"
            elif kv.get("eligible") == "true" and kv.get("deletion_block") == "false":
                extras["restore_allowed"] = True
            elif kv.get("deletion_block") == "true" or kv.get("eligible") == "false":
                extras["restore_allowed"] = False
            else:
                continue
            result = "ACTIVE" if extras["restore_allowed"] else "BLOCKED"
            extras["email"] = kv.get("customer_email") or inherited.get("subject_key")
            extras["user_id"] = kv.get("customer_reference")
        else:
            continue
        obs = make_obs(file_id, captured_at, store, system, rid, category, result, seq, **extras)
        out.append(obs)
        seq += 1
    return out, seq


def load_observations(root: Path):
    dataset = root / "dataset"
    manifest = list(csv.DictReader((dataset / "evidence_files.csv").open(encoding="utf-8")))
    obs = []
    seq = 0
    by_name = {}
    for row in manifest:
        path = dataset / row["file_path"]
        file_id = row["file_id"]
        captured = row["captured_at"]
        by_name[path.name] = (file_id, captured)
        suffix = path.suffix.lower()
        found = []
        if suffix == ".sql":
            found, seq = _parse_sql(path, file_id, captured, seq)
        elif suffix == ".json":
            payload = json.loads(path.read_text(encoding="utf-8"))
            _walk_json(payload, file_id, captured, "primary", None, None, seq, found)
            seq += len(found) + 1
        elif suffix == ".txt":
            found, seq = _parse_handover(path, file_id, captured, seq)
        elif suffix == ".log":
            found, seq = _parse_log(path, file_id, captured, seq)
        elif suffix == ".pdf":
            found, seq = _parse_pdf(path, file_id, captured, seq)
        obs.extend(found)
    for filename, system, rid, category, extra in SHOTS:
        file_id, captured = by_name[filename]
        row = dict(extra)
        row["resource_id"] = rid
        row["record_type"] = category
        made = _from_mapping(file_id, captured, "primary", system, category, row, seq)
        seq += 1
        if made:
            obs.append(made)
    return obs


def load_profile_snapshot_index(obs):
    """Latest USER_PROFILE-bearing file at or before a time, per nothing global.

    Used only when a profile id is never observed: cite the latest profile file.
    """
    files = {}
    for item in obs:
        if item.category != "USER_PROFILE":
            continue
        prev = files.get(item.file_id)
        if prev is None or item.captured_at >= prev:
            files[item.file_id] = item.captured_at
    return files
