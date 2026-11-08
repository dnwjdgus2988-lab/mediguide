"""SQLite 저장소: 의료기기, 점검(스캔), 취약점. EC2 디스크에 파일로 저장되어 별도 DB 신청이 필요 없다."""
import sqlite3
from contextlib import contextmanager
from datetime import datetime

from core.config import DB_PATH

SEVERITIES = ["Critical", "High", "Medium", "Low"]

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    model TEXT, maker TEXT, category TEXT, description TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    device_id INTEGER NOT NULL REFERENCES devices(id),
    version TEXT, source_name TEXT,
    status TEXT NOT NULL,              -- 진행중 | 완료 | 실패
    engine TEXT, files_scanned INTEGER DEFAULT 0,
    score INTEGER, grade TEXT,
    n_critical INTEGER DEFAULT 0, n_high INTEGER DEFAULT 0,
    n_medium INTEGER DEFAULT 0, n_low INTEGER DEFAULT 0,
    error TEXT,
    started_at TEXT NOT NULL, finished_at TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    rule_id TEXT, cwe TEXT, severity TEXT, title TEXT,
    file TEXT, line INTEGER, end_line INTEGER, code TEXT, message TEXT
);
"""


def _now():
    return datetime.now().isoformat(timespec="seconds")


@contextmanager
def conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init_db():
    with conn() as c:
        c.executescript(SCHEMA)


# ── 의료기기 ────────────────────────────────────────────────
def add_device(name, model="", maker="", category="", description=""):
    with conn() as c:
        n = c.execute("SELECT COUNT(*) FROM devices").fetchone()[0] + 1
        code = f"DEV-{n:03d}"
        c.execute(
            "INSERT INTO devices(code,name,model,maker,category,description,created_at) VALUES(?,?,?,?,?,?,?)",
            (code, name, model, maker, category, description, _now()),
        )
        return code


def list_devices():
    with conn() as c:
        return [dict(r) for r in c.execute(
            """SELECT d.*, COUNT(s.id) AS scan_count, MAX(s.started_at) AS last_scan
               FROM devices d LEFT JOIN scans s ON s.device_id=d.id
               GROUP BY d.id ORDER BY d.id DESC""")]


def get_device(device_id):
    with conn() as c:
        r = c.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
        return dict(r) if r else None


# ── 점검 ────────────────────────────────────────────────────
def create_scan(device_id, version, source_name):
    with conn() as c:
        dev = c.execute("SELECT code FROM devices WHERE id=?", (device_id,)).fetchone()
        n = c.execute("SELECT COUNT(*) FROM scans WHERE device_id=?", (device_id,)).fetchone()[0] + 1
        code = f"{dev['code']}-SCN-{n}"
        cur = c.execute(
            "INSERT INTO scans(code,device_id,version,source_name,status,started_at) VALUES(?,?,?,?,?,?)",
            (code, device_id, version, source_name, "진행중", _now()),
        )
        return cur.lastrowid


def finish_scan(scan_id, findings, score, grade, engine, files_scanned, error=None):
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    with conn() as c:
        c.executemany(
            """INSERT INTO findings(scan_id,rule_id,cwe,severity,title,file,line,end_line,code,message)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            [(scan_id, f["rule_id"], f["cwe"], f["severity"], f["title"], f["file"],
              f["line"], f["end_line"], f["code"], f["message"]) for f in findings],
        )
        c.execute(
            """UPDATE scans SET status=?, engine=?, files_scanned=?, score=?, grade=?,
               n_critical=?, n_high=?, n_medium=?, n_low=?, error=?, finished_at=? WHERE id=?""",
            ("실패" if error else "완료", engine, files_scanned, score, grade,
             counts["Critical"], counts["High"], counts["Medium"], counts["Low"], error, _now(), scan_id),
        )


def list_scans(limit=None, device_id=None):
    q = """SELECT s.*, d.name AS device_name, d.code AS device_code
           FROM scans s JOIN devices d ON d.id=s.device_id"""
    args = []
    if device_id:
        q += " WHERE s.device_id=?"
        args.append(device_id)
    q += " ORDER BY s.id DESC"
    if limit:
        q += f" LIMIT {int(limit)}"
    with conn() as c:
        return [dict(r) for r in c.execute(q, args)]


def get_scan(scan_id):
    with conn() as c:
        r = c.execute(
            """SELECT s.*, d.name AS device_name, d.code AS device_code, d.model, d.maker, d.category
               FROM scans s JOIN devices d ON d.id=s.device_id WHERE s.id=?""", (scan_id,)).fetchone()
        return dict(r) if r else None


def findings_for_scan(scan_id):
    order = "CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END"
    with conn() as c:
        return [dict(r) for r in c.execute(
            f"SELECT * FROM findings WHERE scan_id=? ORDER BY {order}, file, line", (scan_id,))]


# ── 대시보드 집계 ───────────────────────────────────────────
def stats():
    with conn() as c:
        devices = c.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        done = c.execute("SELECT COUNT(*) FROM scans WHERE status='완료'").fetchone()[0]
        running = c.execute("SELECT COUNT(*) FROM scans WHERE status='진행중'").fetchone()[0]
        sev = {s: 0 for s in SEVERITIES}
        for r in c.execute("SELECT severity, COUNT(*) n FROM findings GROUP BY severity"):
            if r["severity"] in sev:
                sev[r["severity"]] = r["n"]
        return {"devices": devices, "scans_done": done, "scans_running": running,
                "findings": sum(sev.values()), "severity": sev}


def top_risky_devices(n=5):
    """기기별 '가장 최근 완료 점검' 기준 위험도 상위 n개."""
    with conn() as c:
        rows = c.execute(
            """SELECT d.name, d.code, s.code AS scan_code, s.grade, s.score,
                      s.n_critical, s.n_high, s.n_medium, s.n_low
               FROM devices d JOIN scans s ON s.id = (
                   SELECT id FROM scans WHERE device_id=d.id AND status='완료' ORDER BY id DESC LIMIT 1)
               ORDER BY (s.n_critical*1000 + s.n_high*100 + s.n_medium*10 + s.n_low) DESC
               LIMIT ?""", (n,)).fetchall()
        return [dict(r) for r in rows]
