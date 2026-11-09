"""SQLite 저장소. EC2 디스크에 파일로 저장되어 별도 DB 서버·신청이 필요 없다.

테이블: users, devices, device_history, scans, findings, evidence, assessments,
        reports, std_status, policies, audit_logs, ai_cache
"""
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime

from core.config import DB_PATH

SEVERITIES = ["Critical", "High", "Medium", "Low"]

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL, email TEXT, role TEXT NOT NULL,      -- 관리자 | 검증자 | 열람자
    org TEXT, phone TEXT, pw_hash TEXT NOT NULL, active INTEGER DEFAULT 1,
    last_login TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL, name TEXT NOT NULL, model TEXT, maker TEXT, name_en TEXT, maker_en TEXT,
    device_class TEXT, sw_version TEXT, fw_version TEXT, description TEXT,
    target_market TEXT DEFAULT '미국 FDA', submission_path TEXT DEFAULT '510(k)',
    is_modification INTEGER DEFAULT 0,
    has_software INTEGER, internet INTEGER, vuln_tech INTEGER,        -- 사이버 기기 판정 3문항 (1/0/NULL)
    status TEXT DEFAULT '등록완료', created_at TEXT NOT NULL, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS device_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT, device_id INTEGER NOT NULL,
    field TEXT, old TEXT, new TEXT, user TEXT, at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL, device_id INTEGER NOT NULL REFERENCES devices(id),
    version TEXT, source_name TEXT, source_sha256 TEXT, uploader TEXT,
    status TEXT NOT NULL,                               -- 진행중 | 완료 | 실패
    engine TEXT, engine_version TEXT, ruleset TEXT, ruleset_sha256 TEXT,
    files_scanned INTEGER DEFAULT 0, lines_scanned INTEGER DEFAULT 0, languages TEXT,
    excluded_files INTEGER DEFAULT 0, duration_sec REAL,
    n_critical INTEGER DEFAULT 0, n_high INTEGER DEFAULT 0, n_medium INTEGER DEFAULT 0,
    n_low INTEGER DEFAULT 0, n_other INTEGER DEFAULT 0,
    steps TEXT, error TEXT, started_at TEXT NOT NULL, finished_at TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    rule_id TEXT, cwe TEXT, severity TEXT, title TEXT, cvss TEXT,
    file TEXT, line INTEGER, end_line INTEGER, code TEXT, snippet TEXT, snippet_start INTEGER,
    message TEXT,
    disposition TEXT DEFAULT '검토 필요',                 -- 확인된 결함 | 약점 | 오탐 | 연기 | 검토 필요
    assessed_severity TEXT, rationale TEXT, action TEXT, triaged_by TEXT, triaged_at TEXT
);
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT, device_id INTEGER NOT NULL,
    slot TEXT NOT NULL, filename TEXT, stored TEXT, size INTEGER, sha256 TEXT,
    version TEXT, uploader TEXT, uploaded_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS assessments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL, device_id INTEGER NOT NULL, round INTEGER NOT NULL,
    answers TEXT NOT NULL, score REAL, grade TEXT, progress REAL,
    status TEXT NOT NULL,                               -- 작성중 | 검토대기 | 승인완료 | 반려 | 완료
    evaluator TEXT, requested_by TEXT, requested_at TEXT,
    reviewer TEXT, reviewed_at TEXT, review_comment TEXT,
    created_at TEXT NOT NULL, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL, device_id INTEGER NOT NULL,
    assessment_id INTEGER, scan_id INTEGER, kind TEXT DEFAULT '보안성 검증 리포트',
    score REAL, grade TEXT, status TEXT DEFAULT '발행완료',   -- 발행완료 | 폐기
    snapshot TEXT NOT NULL, issued_by TEXT, created_at TEXT NOT NULL, revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS std_status (
    device_id INTEGER NOT NULL, req_id TEXT NOT NULL, status TEXT, memo TEXT,
    user TEXT, at TEXT, PRIMARY KEY(device_id, req_id)
);
CREATE TABLE IF NOT EXISTS policies (
    key TEXT PRIMARY KEY, description TEXT, value TEXT, category TEXT,
    basis_org TEXT, basis_ref TEXT, updated_by TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, user TEXT, action TEXT,
    target TEXT, ip TEXT
);
CREATE TABLE IF NOT EXISTS sboms (
    scan_id INTEGER PRIMARY KEY, data TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ai_cache (
    key TEXT PRIMARY KEY, answer TEXT, hits TEXT, not_found INTEGER, at TEXT
);
"""


def now():
    return datetime.now().isoformat(timespec="seconds")


@contextmanager
def conn():
    c = sqlite3.connect(DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init_db():
    with conn() as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript(SCHEMA)


def q(sql, args=()):
    with conn() as c:
        return [dict(r) for r in c.execute(sql, args)]


def one(sql, args=()):
    rows = q(sql, args)
    return rows[0] if rows else None


def run(sql, args=()):
    with conn() as c:
        cur = c.execute(sql, args)
        return cur.lastrowid


def insert(table, data: dict):
    cols = ",".join(data)
    marks = ",".join("?" * len(data))
    return run(f"INSERT INTO {table}({cols}) VALUES({marks})", tuple(data.values()))


def update(table, row_id, data: dict, key="id"):
    if not data:
        return
    sets = ",".join(f"{k}=?" for k in data)
    run(f"UPDATE {table} SET {sets} WHERE {key}=?", (*data.values(), row_id))


def jload(s, default=None):
    if not s:
        return default
    try:
        return json.loads(s)
    except (TypeError, ValueError):
        return default


def jdump(o):
    return json.dumps(o, ensure_ascii=False)


def audit(user, action, target="", ip=""):
    insert("audit_logs", {"at": now(), "user": user or "system", "action": action, "target": target, "ip": ip or ""})
