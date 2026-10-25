"""Ghost Data Still Exists: offline deletion audit.

Reads dataset/ and writes output.csv at the repository root.
"""

from __future__ import annotations

import csv
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from evidence import DELETE_CATS, ANON_CATS, REDACT_CATS, RETAIN_CATS, load_observations

ROOT = Path(__file__).resolve().parents[1]
NON_DELETION = re.compile(
    r"do not close|not asking for deletion|not a request to erase|don't delete|"
    r"without removing|marketing lists only|portable format|leave my profile|"
    r"leave the account active|change the email address|promotional emails",
    re.I,
)
TARGET_RE = re.compile(r"Target resource: (\S+)")
OP_RANK = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 4,
    "BLOCK_RESTORE": 5,
    "DELETE_RECORD": 6,
    "REDACT_RECORD": 7,
    "ANONYMIZE_RECORD": 8,
    "VERIFY_RECORD_ABSENT": 9,
    "VERIFY_RECORD_PRESENT": 10,
    "VERIFY_RECORD_REDACTED": 11,
    "VERIFY_RECORD_ANONYMIZED": 12,
    "VERIFY_DATA_FLOW_DISABLED": 13,
    "VERIFY_RESTORE_BLOCKED": 14,
}
PHASE_RANK = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}


def _when(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _digits(value):
    return re.sub(r"\D", "", value or "")


def _file_num(file_id):
    return int(file_id.split("_")[1]) if file_id and file_id.startswith("evidence_") else 0


def load_world(root=ROOT):
    obs = load_observations(root)
    users = {}
    for row in csv.DictReader((root / "dataset" / "user_identities.csv").open(encoding="utf-8")):
        users[row["user_id"]] = {
            "user_id": row["user_id"],
            "email": row["email"],
            "phone": row["phone"],
            "email_hash": row["email_hash"],
            "updated_at": row["updated_at"],
            "events": [],
        }
    by_email = defaultdict(list)
    for user in users.values():
        by_email[user["email"].lower()].append(user["user_id"])
    for row in csv.DictReader((root / "dataset" / "user_audit_log.csv").open(encoding="utf-8")):
        user = users.get(row["user_id"])
        if not user:
            continue
        user["events"].append(row)
        if row["field_name"] == "email":
            by_email[row["old_value"].lower()].append(row["user_id"])
            by_email[row["new_value"].lower()].append(row["user_id"])
    requests = list(csv.DictReader((root / "dataset" / "deletion_requests.csv").open(encoding="utf-8")))
    activities = []
    for row in csv.DictReader((root / "dataset" / "system_activity.csv").open(encoding="utf-8")):
        match = TARGET_RE.search(row["details"])
        if match:
            activities.append((row["event_time"], match.group(1).rstrip(".")))
    reported = defaultdict(int)
    for row in requests:
        reported[row["reported_at"]] += 1
    non_deletion = sum(1 for row in requests if NON_DELETION.search(row["request_text"]))
    if non_deletion != 10:
        raise SystemExit(f"expected 10 non-deletion requests, found {non_deletion}")
    return obs, users, by_email, requests, activities, reported


def identifiers(user, audit_at):
    emails, phones, hashes = set(), set(), set()
    user_ids = {user["user_id"]}

    def add(field, value):
        if not value:
            return
        if field == "email":
            emails.add(value.lower())
        elif field == "phone":
            digits = _digits(value)
            if digits:
                phones.add(digits)
        elif field == "email_hash":
            hashes.add(value.lower())

    if user["updated_at"] <= audit_at:
        add("email", user["email"])
        add("phone", user["phone"])
        add("email_hash", user["email_hash"])
    for event in user["events"]:
        if event["event_time"] <= audit_at:
            add(event["field_name"], event["old_value"])
            add(event["field_name"], event["new_value"])
        else:
            add(event["field_name"], event["old_value"])
    if not emails:
        add("email", user["email"])
    return emails, phones, hashes, user_ids


def resolve_user(email, users, by_email):
    ids = by_email.get(email.lower(), [])
    if not ids:
        return None
    return users[ids[0]]


def _matches(obs, idents):
    emails, phones, hashes, user_ids = idents
    if set(obs.emails) & emails or set(obs.phones) & phones:
        return True
    if set(obs.hashes) & hashes or set(obs.user_ids) & user_ids:
        return True
    return False


def _violates(obs, audit_at):
    if obs.category in RETAIN_CATS and obs.present:
        if obs.retention_until and obs.retention_until < audit_at:
            return True
        return False
    if not obs.present:
        return False
    if obs.category in DELETE_CATS:
        return True
    if obs.category in ANON_CATS:
        return bool(obs.pii) and not obs.anonymized
    if obs.category in REDACT_CATS:
        return bool(obs.pii) and not obs.redacted
    if obs.category == "DATA_FLOW":
        return obs.flow_enabled is True
    if obs.category == "BACKUP_ARCHIVE":
        return obs.restore_allowed is True
    return False


def _plan(obs, violation):
    """Return finding op, remediation op, verification op, states. None to omit."""
    cat = obs.category
    if violation:
        if cat in DELETE_CATS or (cat in RETAIN_CATS and not _retained(obs)):
            return (
                "REPORT_REMAINING_RECORD",
                "PRESENT",
                "DELETE_RECORD",
                "ABSENT",
                "VERIFY_RECORD_ABSENT",
                "ABSENT",
            )
        if cat in ANON_CATS:
            return (
                "REPORT_EXPOSED_PII",
                "PRESENT",
                "ANONYMIZE_RECORD",
                "ANONYMIZED",
                "VERIFY_RECORD_ANONYMIZED",
                "ANONYMIZED",
            )
        if cat in REDACT_CATS:
            return (
                "REPORT_EXPOSED_PII",
                "PRESENT",
                "REDACT_RECORD",
                "REDACTED",
                "VERIFY_RECORD_REDACTED",
                "REDACTED",
            )
        if cat == "DATA_FLOW":
            return (
                "REPORT_ACTIVE_DATA_FLOW",
                "ACTIVE",
                "DISABLE_DATA_FLOW",
                "DISABLED",
                "VERIFY_DATA_FLOW_DISABLED",
                "DISABLED",
            )
        if cat == "BACKUP_ARCHIVE":
            return (
                "REPORT_RESTORE_RISK",
                "ACTIVE",
                "BLOCK_RESTORE",
                "BLOCKED",
                "VERIFY_RESTORE_BLOCKED",
                "BLOCKED",
            )
        return None
    if cat == "USER_PROFILE" and not obs.present:
        return (None, None, None, None, "VERIFY_RECORD_ABSENT", "ABSENT")
    if cat in ANON_CATS and obs.present and (obs.anonymized or not obs.pii):
        return (None, None, None, None, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED")
    if cat in REDACT_CATS and obs.present and (obs.redacted or not obs.pii):
        return (None, None, None, None, "VERIFY_RECORD_REDACTED", "REDACTED")
    if cat in RETAIN_CATS and obs.present:
        return (None, None, None, None, "VERIFY_RECORD_PRESENT", "PRESENT")
    if cat == "DATA_FLOW" and obs.flow_enabled is False:
        return (None, None, None, None, "VERIFY_DATA_FLOW_DISABLED", "DISABLED")
    if cat == "BACKUP_ARCHIVE" and obs.present and obs.restore_allowed is False:
        return (None, None, None, None, "VERIFY_RESTORE_BLOCKED", "BLOCKED")
    return None


def _retained(obs):
    return obs.category in RETAIN_CATS and obs.present and not (
        obs.retention_until and False
    )


def _choose(group, audit_at):
    latest = {}
    for item in group:
        key = item.store
        prev = latest.get(key)
        rank = (item.captured_at, _file_num(item.file_id), item.seq)
        if prev is None or rank >= (prev.captured_at, _file_num(prev.file_id), prev.seq):
            latest[key] = item
    chosen_bad = [item for item in latest.values() if _violates(item, audit_at)]
    if chosen_bad:
        pick = max(chosen_bad, key=lambda item: (item.captured_at, _file_num(item.file_id), item.seq))
        return pick, True
    present = [item for item in latest.values() if item.present]
    pool = present or list(latest.values())
    pick = max(pool, key=lambda item: (item.captured_at, _file_num(item.file_id), item.seq))
    return pick, False


def _step(phase, system_id, resource_id, operation, state, evidence_id):
    return {
        "phase": phase,
        "system_id": system_id,
        "resource_id": resource_id,
        "operation": operation,
        "state": state,
        "evidence_id": evidence_id,
    }


def audit_case(case, obs, users, by_email, activities, reported, profile_files):
    if NON_DELETION.search(case["request_text"]):
        return {"case_id": case["case_id"], "deletion_status": "NOT_APPLICABLE", "steps_json": []}
    user = resolve_user(case["email"], users, by_email)
    if user is None:
        return {"case_id": case["case_id"], "deletion_status": "INCOMPLETE", "steps_json": []}
    audit_at = case["audit_at"]
    idents = identifiers(user, audit_at)
    linked = set()
    for item in obs:
        if item.captured_at <= audit_at and _matches(item, idents):
            linked.add(item.resource_id)
    if reported[case["reported_at"]] == 1:
        moment = _when(case["reported_at"])
        window = timedelta(minutes=20)
        for event_time, resource_id in activities:
            if abs(_when(event_time) - moment) <= window:
                linked.add(resource_id)
    if not any(rid.startswith("account_") for rid in linked):
        number = int(user["user_id"].split("_")[1])
        linked.add(f"account_{number:03d}")
    steps = []
    seen = set()
    for resource_id in linked:
        group = [item for item in obs if item.resource_id == resource_id and item.captured_at <= audit_at]
        if not group and resource_id.startswith("account_"):
            earlier = [(stamp, file_id) for file_id, stamp in profile_files.items() if stamp <= audit_at]
            if not earlier:
                continue
            stamp, file_id = max(earlier)
            from evidence import Obs

            group = [
                Obs(
                    file_id=file_id,
                    captured_at=stamp,
                    store="primary",
                    system_id="account_service",
                    resource_id=resource_id,
                    category="USER_PROFILE",
                    present=False,
                )
            ]
        if not group:
            continue
        chosen, violation = _choose(group, audit_at)
        planned = _plan(chosen, violation)
        if not planned:
            continue
        find_op, find_state, rem_op, rem_state, ver_op, ver_state = planned
        key = (chosen.system_id, chosen.resource_id, ver_op)
        if key in seen:
            continue
        seen.add(key)
        cite = chosen.file_id
        if find_op:
            steps.append(("finding", _step("FINDING", chosen.system_id, chosen.resource_id, find_op, find_state, cite)))
            steps.append(("rem", _step("REMEDIATION", chosen.system_id, chosen.resource_id, rem_op, rem_state, "")))
            steps.append(("ver", _step("VERIFICATION", chosen.system_id, chosen.resource_id, ver_op, ver_state, "")))
        else:
            steps.append(("ver", _step("VERIFICATION", chosen.system_id, chosen.resource_id, ver_op, ver_state, cite)))
    findings = [step for kind, step in steps if kind == "finding"]
    status = "COMPLETE" if not findings else "INCOMPLETE"
    if status == "COMPLETE":
        body = [step for kind, step in steps if kind == "ver"]
    else:
        body = [step for kind, step in steps]
        for step in body:
            if step["phase"] != "FINDING":
                step["evidence_id"] = ""
    body.sort(key=lambda step: (PHASE_RANK[step["phase"]], OP_RANK[step["operation"]], step["system_id"], step["resource_id"]))
    for number, step in enumerate(body, start=1):
        step["step_no"] = number
    ordered = [
        {
            "step_no": step["step_no"],
            "phase": step["phase"],
            "system_id": step["system_id"],
            "resource_id": step["resource_id"],
            "operation": step["operation"],
            "state": step["state"],
            "evidence_id": step["evidence_id"],
        }
        for step in body
    ]
    return {"case_id": case["case_id"], "deletion_status": status, "steps_json": ordered}


def profile_files(obs):
    files = {}
    for item in obs:
        if item.category == "USER_PROFILE" and item.present:
            prev = files.get(item.file_id)
            if prev is None or item.captured_at > prev:
                files[item.file_id] = item.captured_at
    return files


def evaluate_requests(requests, world=None):
    obs, users, by_email, _all, activities, reported = world or load_world()
    files = profile_files(obs)
    return [
        audit_case(case, obs, users, by_email, activities, reported, files) for case in requests
    ]


def write_output(rows, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        for row in sorted(rows, key=lambda item: int(item["case_id"].split("_")[1])):
            writer.writerow(
                {
                    "case_id": row["case_id"],
                    "deletion_status": row["deletion_status"],
                    "steps_json": json.dumps(row["steps_json"], separators=(",", ":")),
                }
            )


def main():
    world = load_world()
    rows = evaluate_requests(world[3], world)
    write_output(rows, ROOT / "output.csv")
    print(f"wrote {len(rows)} rows to {ROOT / 'output.csv'}")


if __name__ == "__main__":
    main()
