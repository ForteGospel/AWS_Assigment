import json
import os
import sqlite3
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(__file__), "findings.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    status      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
    scan_id       INTEGER NOT NULL,
    account_id    TEXT NOT NULL,
    account_name  TEXT,
    is_management INTEGER NOT NULL,
    status        TEXT NOT NULL,
    error         TEXT,
    PRIMARY KEY (scan_id, account_id),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS instances (
    scan_id              INTEGER NOT NULL,
    account_id           TEXT NOT NULL,
    region               TEXT NOT NULL,
    instance_id          TEXT NOT NULL,
    state                TEXT,
    public_ip            TEXT,
    private_ip           TEXT,
    instance_type        TEXT,
    metadata_http_tokens TEXT,
    raw_json             TEXT NOT NULL,
    PRIMARY KEY (scan_id, account_id, instance_id),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS security_groups (
    scan_id       INTEGER NOT NULL,
    account_id    TEXT NOT NULL,
    region        TEXT NOT NULL,
    group_id      TEXT NOT NULL,
    group_name    TEXT,
    is_world_open INTEGER NOT NULL,
    raw_json      TEXT NOT NULL,
    PRIMARY KEY (scan_id, account_id, group_id),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS volumes (
    scan_id              INTEGER NOT NULL,
    account_id           TEXT NOT NULL,
    region               TEXT NOT NULL,
    volume_id            TEXT NOT NULL,
    encrypted            INTEGER NOT NULL,
    size_gb              INTEGER,
    state                TEXT,
    attached_instance_id TEXT,
    raw_json             TEXT NOT NULL,
    PRIMARY KEY (scan_id, account_id, volume_id),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL,
    account_id  TEXT NOT NULL,
    severity    TEXT NOT NULL,
    region      TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    issue       TEXT NOT NULL,
    details     TEXT NOT NULL,
    remediation TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_resource ON findings(scan_id, account_id, resource_id);
CREATE INDEX IF NOT EXISTS idx_instances_scan_region ON instances(scan_id, account_id, region);
"""


def _to_json(obj):
    return json.dumps(obj, default=str)


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _schema_is_current(conn):
    # accounts table exists only in the multi-account schema
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='accounts'"
    ).fetchone()
    return row is not None


def init_db():
    with connect() as conn:
        existing_tables = [
            r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        ]
        if existing_tables and not _schema_is_current(conn):
            # Pre-org-level schema present — drop and recreate.
            for table in ["findings", "volumes", "security_groups", "instances", "scans", "accounts"]:
                conn.execute(f"DROP TABLE IF EXISTS {table}")
        conn.executescript(SCHEMA)


def start_scan():
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO scans (started_at, status) VALUES (?, ?)",
            (_now(), "running"),
        )
        return cur.lastrowid


def finish_scan(scan_id, status="completed"):
    with connect() as conn:
        conn.execute(
            "UPDATE scans SET finished_at = ?, status = ? WHERE id = ?",
            (_now(), status, scan_id),
        )


def insert_account(scan_id, account):
    with connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO accounts "
            "(scan_id, account_id, account_name, is_management, status, error) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                scan_id,
                account["account_id"],
                account.get("account_name"),
                1 if account.get("is_management") else 0,
                account.get("status", "unknown"),
                account.get("error"),
            ),
        )


def insert_region_result(scan_id, account_id, region_result):
    region = region_result["region"]
    world_open_ids = set(region_result.get("world_open_security_group_ids", []))

    with connect() as conn:
        for inst in region_result["instances"]:
            metadata = inst.get("MetadataOptions") or {}
            conn.execute(
                "INSERT OR REPLACE INTO instances "
                "(scan_id, account_id, region, instance_id, state, public_ip, private_ip, instance_type, metadata_http_tokens, raw_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    scan_id,
                    account_id,
                    region,
                    inst.get("InstanceId"),
                    (inst.get("State") or {}).get("Name"),
                    inst.get("PublicIpAddress"),
                    inst.get("PrivateIpAddress"),
                    inst.get("InstanceType"),
                    metadata.get("HttpTokens"),
                    _to_json(inst),
                ),
            )

        for group_id, group in region_result["security_groups"].items():
            conn.execute(
                "INSERT OR REPLACE INTO security_groups "
                "(scan_id, account_id, region, group_id, group_name, is_world_open, raw_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    scan_id,
                    account_id,
                    region,
                    group_id,
                    group.get("GroupName"),
                    1 if group_id in world_open_ids else 0,
                    _to_json(group),
                ),
            )

        for volume_id, volume in region_result["volumes"].items():
            attachments = volume.get("Attachments") or []
            attached_instance_id = attachments[0].get("InstanceId") if attachments else None
            conn.execute(
                "INSERT OR REPLACE INTO volumes "
                "(scan_id, account_id, region, volume_id, encrypted, size_gb, state, attached_instance_id, raw_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    scan_id,
                    account_id,
                    region,
                    volume_id,
                    1 if volume.get("Encrypted") else 0,
                    volume.get("Size"),
                    volume.get("State"),
                    attached_instance_id,
                    _to_json(volume),
                ),
            )

        for finding in region_result["findings"]:
            resource_id = finding["resource"].split(" ", 1)[0]
            conn.execute(
                "INSERT INTO findings (scan_id, account_id, severity, region, resource_id, issue, details, remediation) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    scan_id,
                    account_id,
                    finding["severity"],
                    region,
                    resource_id,
                    finding["issue"],
                    finding["details"],
                    finding["remediation"],
                ),
            )


def latest_scan():
    """Most recent scan of any status — so in-progress scans surface in the UI."""
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return dict(row) if row else None


def scan_summary(scan_id):
    with connect() as conn:
        instance_count = conn.execute(
            "SELECT COUNT(*) AS c FROM instances WHERE scan_id = ?", (scan_id,)
        ).fetchone()["c"]
        sg_count = conn.execute(
            "SELECT COUNT(*) AS c FROM security_groups WHERE scan_id = ?", (scan_id,)
        ).fetchone()["c"]
        volume_count = conn.execute(
            "SELECT COUNT(*) AS c FROM volumes WHERE scan_id = ?", (scan_id,)
        ).fetchone()["c"]
        findings_by_severity = {
            row["severity"]: row["c"]
            for row in conn.execute(
                "SELECT severity, COUNT(*) AS c FROM findings WHERE scan_id = ? GROUP BY severity",
                (scan_id,),
            ).fetchall()
        }
        regions = [
            r["region"]
            for r in conn.execute(
                "SELECT DISTINCT region FROM instances WHERE scan_id = ? "
                "UNION SELECT DISTINCT region FROM security_groups WHERE scan_id = ? "
                "UNION SELECT DISTINCT region FROM volumes WHERE scan_id = ? "
                "ORDER BY region",
                (scan_id, scan_id, scan_id),
            ).fetchall()
        ]
        accounts = [
            dict(r) for r in conn.execute(
                "SELECT * FROM accounts WHERE scan_id = ? ORDER BY is_management DESC, account_id",
                (scan_id,),
            ).fetchall()
        ]

    completed_accounts = [a for a in accounts if a["status"] == "completed"]
    failed_accounts = [a for a in accounts if a["status"] not in ("completed",)]

    return {
        "instance_count": instance_count,
        "security_group_count": sg_count,
        "volume_count": volume_count,
        "findings_by_severity": findings_by_severity,
        "regions": regions,
        "accounts": accounts,
        "completed_account_count": len(completed_accounts),
        "failed_accounts": failed_accounts,
    }


def list_accounts(scan_id):
    with connect() as conn:
        return [
            dict(r) for r in conn.execute(
                "SELECT * FROM accounts WHERE scan_id = ? ORDER BY is_management DESC, account_id",
                (scan_id,),
            ).fetchall()
        ]


def list_instances(scan_id, region=None, has_issue=None, account_id=None):
    query = (
        "SELECT i.*, "
        "(SELECT COUNT(*) FROM findings f WHERE f.scan_id = i.scan_id AND f.account_id = i.account_id AND f.resource_id = i.instance_id) AS issue_count "
        "FROM instances i WHERE i.scan_id = ?"
    )
    params = [scan_id]
    if account_id:
        query += " AND i.account_id = ?"
        params.append(account_id)
    if region:
        query += " AND i.region = ?"
        params.append(region)
    query += " ORDER BY i.account_id, i.region, i.instance_id"

    with connect() as conn:
        rows = [dict(r) for r in conn.execute(query, params).fetchall()]

    if has_issue == "yes":
        rows = [r for r in rows if r["issue_count"] > 0]
    elif has_issue == "no":
        rows = [r for r in rows if r["issue_count"] == 0]
    return rows


def list_security_groups(scan_id, region=None, account_id=None):
    query = "SELECT * FROM security_groups WHERE scan_id = ?"
    params = [scan_id]
    if account_id:
        query += " AND account_id = ?"
        params.append(account_id)
    if region:
        query += " AND region = ?"
        params.append(region)
    query += " ORDER BY account_id, region, group_id"
    with connect() as conn:
        return [dict(r) for r in conn.execute(query, params).fetchall()]


def list_volumes(scan_id, region=None, account_id=None):
    query = "SELECT * FROM volumes WHERE scan_id = ?"
    params = [scan_id]
    if account_id:
        query += " AND account_id = ?"
        params.append(account_id)
    if region:
        query += " AND region = ?"
        params.append(region)
    query += " ORDER BY region, volume_id"
    with connect() as conn:
        return [dict(r) for r in conn.execute(query, params).fetchall()]


def list_findings(scan_id, severity=None, region=None, issue_substring=None, account_id=None):
    query = "SELECT * FROM findings WHERE scan_id = ?"
    params = [scan_id]
    if account_id:
        query += " AND account_id = ?"
        params.append(account_id)
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if region:
        query += " AND region = ?"
        params.append(region)
    if issue_substring:
        query += " AND issue LIKE ?"
        params.append(f"%{issue_substring}%")
    query += " ORDER BY severity DESC, account_id, region, resource_id"
    with connect() as conn:
        return [dict(r) for r in conn.execute(query, params).fetchall()]


def get_instance(scan_id, instance_id):
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM instances WHERE scan_id = ? AND instance_id = ?",
            (scan_id, instance_id),
        ).fetchone()
        if not row:
            return None
        instance = dict(row)
        instance["raw"] = json.loads(instance["raw_json"])
        account_id = instance["account_id"]

        attached_sg_ids = [g["GroupId"] for g in instance["raw"].get("SecurityGroups", [])]
        if attached_sg_ids:
            placeholders = ",".join("?" * len(attached_sg_ids))
            sg_rows = conn.execute(
                f"SELECT * FROM security_groups WHERE scan_id = ? AND account_id = ? AND group_id IN ({placeholders})",
                [scan_id, account_id, *attached_sg_ids],
            ).fetchall()
            instance["security_groups"] = [dict(r) for r in sg_rows]
        else:
            instance["security_groups"] = []

        vol_rows = conn.execute(
            "SELECT * FROM volumes WHERE scan_id = ? AND account_id = ? AND attached_instance_id = ?",
            (scan_id, account_id, instance_id),
        ).fetchall()
        instance["volumes"] = [dict(r) for r in vol_rows]

        finding_rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? AND account_id = ? AND resource_id = ? ORDER BY severity DESC",
            (scan_id, account_id, instance_id),
        ).fetchall()
        instance["findings"] = [dict(r) for r in finding_rows]

        return instance
