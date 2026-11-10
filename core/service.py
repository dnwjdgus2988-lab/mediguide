"""업무 로직: 사용자·의료기기·증빙·정적분석·평가(체크리스트)·리포트·대시보드 통계."""
import hashlib
import json
import os
import secrets
import shutil
import threading
from datetime import datetime
from pathlib import Path

from core import checklist, db, policy, sbom, scanner, standards
from core.config import UPLOADS

SEV = ["Critical", "High", "Medium", "Low"]


# ══ 사용자 ═══════════════════════════════════════════════════
def hash_pw(pw: str):
    salt = secrets.token_hex(8)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000).hex()
    return f"{salt}${h}"


def check_pw(pw: str, stored: str):
    try:
        salt, h = stored.split("$", 1)
    except ValueError:
        return False
    return secrets.compare_digest(hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000).hex(), h)


def create_user(username, password, role="열람자", email="", org="", phone=""):
    return db.insert("users", {"username": username, "email": email, "role": role, "org": org, "phone": phone,
                               "pw_hash": hash_pw(password), "active": 1, "created_at": db.now()})


def authenticate(username, password):
    u = db.one("SELECT * FROM users WHERE username=?", (username,))
    if u and u["active"] and check_pw(password, u["pw_hash"]):
        db.update("users", u["id"], {"last_login": db.now()})
        return u
    return None


def list_users():
    return db.q("SELECT id, username, email, role, org, phone, active, last_login, created_at FROM users ORDER BY id")


# ══ 의료기기 ══════════════════════════════════════════════════
DEVICE_FIELDS = {"name": "기기명", "name_en": "영문 기기명", "model": "모델명", "maker": "제조사명", "maker_en": "영문 제조사명", "device_class": "의료기기유형",
                 "sw_version": "소프트웨어 버전", "fw_version": "펌웨어 버전", "description": "설명",
                 "target_market": "목표 시장", "submission_path": "제출 경로", "is_modification": "변경신청 여부",
                 "has_software": "소프트웨어 포함", "internet": "인터넷 연결", "vuln_tech": "위협 취약 특성"}


def add_device(data: dict, user="system"):
    n = (db.one("SELECT MAX(id) AS m FROM devices")["m"] or 0) + 1
    code = f"DEV-{n:03d}"
    row = {k: data.get(k) for k in DEVICE_FIELDS if k in data}
    row.update(code=code, created_at=db.now(), updated_at=db.now(), status="등록완료")
    dev_id = db.insert("devices", row)
    return dev_id, code


def update_device(dev_id, data: dict, user):
    cur = get_device(dev_id)
    changes = {}
    for k, v in data.items():
        if k in DEVICE_FIELDS and str(cur.get(k) if cur.get(k) is not None else "") != str(v if v is not None else ""):
            changes[k] = v
            db.insert("device_history", {"device_id": dev_id, "field": DEVICE_FIELDS[k], "old": "" if cur.get(k) is None else str(cur.get(k)),
                                         "new": "" if v is None else str(v), "user": user, "at": db.now()})
    if changes:
        changes["updated_at"] = db.now()
        db.update("devices", dev_id, changes)
    return changes


def get_device(dev_id):
    return db.one("SELECT * FROM devices WHERE id=?", (dev_id,))


def get_device_by_code(code):
    return db.one("SELECT * FROM devices WHERE code=?", (code,))


def device_history(dev_id):
    return db.q("SELECT * FROM device_history WHERE device_id=? ORDER BY id DESC", (dev_id,))


def device_state(dev):
    """기기의 현재 판정: 반영 평가(승인완료·완료 중 최신), 채점, 등급, FDA 적합성."""
    asm = db.one("SELECT * FROM assessments WHERE device_id=? AND status IN ('승인완료','완료') ORDER BY round DESC LIMIT 1",
                 (dev["id"],))
    scan = latest_scan(dev["id"])
    sev = sev_counts(scan) if scan else {}
    if not asm:
        return {"assessment": None, "result": None, "grade": None, "fda": checklist.fda_verdict(dev, None, None),
                "scan": scan, "sev": sev}
    res = checklist.score(db.jload(asm["answers"], {}), dev, evidence_slots(dev["id"]))
    grade = checklist.final_grade(res["rate"], sev)
    return {"assessment": asm, "result": res, "grade": grade, "fda": checklist.fda_verdict(dev, res, grade),
            "scan": scan, "sev": sev}


def list_devices_full():
    out = []
    for d in db.q("SELECT * FROM devices ORDER BY id DESC"):
        st = device_state(d)
        d["fda"] = st["fda"]
        d["scan_count"] = db.one("SELECT COUNT(*) AS n FROM scans WHERE device_id=?", (d["id"],))["n"]
        s = st["scan"]
        d["vuln_count"] = sum(st["sev"].values()) if s else 0
        out.append(d)
    return out


# ══ 증빙 ═════════════════════════════════════════════════════
def save_evidence(dev_id, slot, filename, data: bytes, user, version="1.0"):
    folder = UPLOADS / "evidence" / str(dev_id)
    folder.mkdir(parents=True, exist_ok=True)
    safe = "".join(ch for ch in Path(filename).name if ch not in '\\/:*?"<>|') or "file"
    stored = folder / f"{slot}_{datetime.now():%Y%m%d%H%M%S}_{safe}"
    stored.write_bytes(data)
    db.insert("evidence", {"device_id": dev_id, "slot": slot, "filename": safe, "stored": str(stored), "size": len(data),
                           "sha256": hashlib.sha256(data).hexdigest(), "version": version, "uploader": user,
                           "uploaded_at": db.now()})


def evidence_list(dev_id):
    """슬롯별 최신 파일."""
    rows = db.q("SELECT * FROM evidence WHERE device_id=? ORDER BY id", (dev_id,))
    latest = {}
    for r in rows:
        latest[r["slot"]] = r
    return latest


def evidence_slots(dev_id):
    return set(evidence_list(dev_id).keys())


def delete_evidence(dev_id, slot):
    for r in db.q("SELECT * FROM evidence WHERE device_id=? AND slot=?", (dev_id, slot)):
        try:
            os.remove(r["stored"])
        except OSError:
            pass
    db.run("DELETE FROM evidence WHERE device_id=? AND slot=?", (dev_id, slot))


# ══ 정적분석 ══════════════════════════════════════════════════
def sev_counts(scan):
    if not scan:
        return {}
    return {"Critical": scan["n_critical"], "High": scan["n_high"], "Medium": scan["n_medium"], "Low": scan["n_low"]}


def latest_scan(dev_id):
    return db.one("SELECT * FROM scans WHERE device_id=? AND status='완료' ORDER BY id DESC LIMIT 1", (dev_id,))


def list_scans(device_id=None, limit=None):
    sql = """SELECT s.*, d.name AS device_name, d.code AS device_code FROM scans s JOIN devices d ON d.id=s.device_id"""
    args = ()
    if device_id:
        sql += " WHERE s.device_id=?"
        args = (device_id,)
    sql += " ORDER BY s.id DESC"
    if limit:
        sql += f" LIMIT {int(limit)}"
    return db.q(sql, args)


def get_scan(code):
    return db.one("""SELECT s.*, d.name AS device_name, d.code AS device_code FROM scans s
                     JOIN devices d ON d.id=s.device_id WHERE s.code=?""", (code,))


def get_scan_by_id(scan_id):
    return db.one("SELECT * FROM scans WHERE id=?", (scan_id,))


def findings(scan_id):
    return db.q("""SELECT * FROM findings WHERE scan_id=? ORDER BY
                   CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END, file, line""",
                (scan_id,))


def get_finding(fid):
    return db.one("SELECT * FROM findings WHERE id=?", (fid,))


def triage(fid, disposition, assessed_severity, rationale, action, user):
    db.update("findings", fid, {"disposition": disposition, "assessed_severity": assessed_severity, "rationale": rationale,
                                "action": action, "triaged_by": user, "triaged_at": db.now()})


STEP_LABELS = ["파일 업로드 완료", "압축 해제 완료", "소스코드 파싱 완료", "정적분석 실행", "CWE 룰셋 매핑", "SBOM 생성 · 취약점 DB 조회", "보안성 등급 산출", "리포트 생성"]


def start_scan(dev, archive: Path, source_name, version, user, background=True):
    n = db.one("SELECT COUNT(*) AS n FROM scans WHERE device_id=?", (dev["id"],))["n"] + 1
    code = f"{dev['code']}-SCN-{n}"
    steps = [{"label": STEP_LABELS[0], "detail": "", "state": "done"}] + \
            [{"label": s, "detail": "", "state": "wait"} for s in STEP_LABELS[1:]]
    scan_id = db.insert("scans", {"code": code, "device_id": dev["id"], "version": version or dev.get("sw_version") or "",
                                  "source_name": source_name, "source_sha256": scanner.sha256_file(archive),
                                  "uploader": user, "status": "진행중", "ruleset": policy.get("scan.ruleset_label"),
                                  "steps": db.jdump(steps), "started_at": db.now()})
    db.audit(user, "정적분석 시작", f"{dev['name']} v{version or dev.get('sw_version') or ''}")
    if background:
        threading.Thread(target=_run_scan, args=(scan_id, dev, archive, user), daemon=True).start()
    else:
        _run_scan(scan_id, dev, archive, user)
    return code


def _set_step(scan_id, steps, i, state, detail=""):
    steps[i]["state"] = state
    if detail:
        steps[i]["detail"] = detail
    db.update("scans", scan_id, {"steps": db.jdump(steps)})


def _run_scan(scan_id, dev, archive: Path, user):
    steps = db.jload(get_scan_by_id(scan_id)["steps"], [])
    work = UPLOADS / "work" / str(scan_id)
    try:
        _set_step(scan_id, steps, 1, "run")
        if archive.is_dir():
            src = archive
        else:
            if work.exists():
                shutil.rmtree(work, ignore_errors=True)
            src = scanner.safe_extract(archive, work)
        _set_step(scan_id, steps, 1, "done")
        excludes = policy.get("scan.exclude_paths", scanner.DEFAULT_EXCLUDES)
        files, lines, langs, excluded = scanner.inventory(src, {e.strip() for e in excludes.split(",")})
        _set_step(scan_id, steps, 2, "done", f"파일 {files}개")
        name, _ = scanner.find_engine()
        steps[3]["label"] = f"{'Opengrep' if name == 'opengrep' else 'Semgrep'} 정적분석 실행"
        _set_step(scan_id, steps, 3, "run")
        packs = [x.strip() for x in policy.get("scan.community_packs", "p/cwe-top-25").split(",") if x.strip()]
        res = scanner.scan(src, excludes, packs)
        _set_step(scan_id, steps, 3, "done", f"{res['duration']:.0f}초" + (f", 공개 룰팩 {', '.join(res['packs'])} {res['pack_note']}" if res["packs"] else ""))
        cnt = {s: 0 for s in SEV}
        with db.conn() as c:
            for f in res["findings"]:
                cnt[f["severity"]] = cnt.get(f["severity"], 0) + 1
                c.execute("""INSERT INTO findings(scan_id, rule_id, cwe, severity, title, cvss, file, line, end_line, code,
                             snippet, snippet_start, message) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                          (scan_id, f["rule_id"], f["cwe"], f["severity"], f["title"], f["cvss"], f["file"], f["line"],
                           f["end_line"], f["code"], f["snippet"], f["snippet_start"], f["message"]))
        _set_step(scan_id, steps, 4, "done", f"취약점 {len(res['findings'])}건")
        _set_step(scan_id, steps, 5, "run")
        try:
            sb = sbom.generate(src, policy.get("sbom.osv_enabled", "1") == "1")
            db.run("INSERT OR REPLACE INTO sboms(scan_id, data, created_at) VALUES(?,?,?)", (scan_id, db.jdump(sb), db.now()))
            sm = sbom.summary(sb)
            _set_step(scan_id, steps, 5, "done", f"구성요소 {sm['n']}개, 알려진 취약점 {sm['n_vulns']}건" + (" — OSV 조회 실패" if sb["error"] else ""))
        except Exception as e:  # noqa: BLE001 — SBOM 실패가 정적분석 결과를 막지 않게
            _set_step(scan_id, steps, 5, "fail", f"SBOM 생성 실패: {str(e)[:60]}")
        db.update("scans", scan_id, {
            "status": "완료", "engine": res["engine"], "engine_version": res["engine_version"],
            "ruleset_sha256": scanner.ruleset_sha256(), "files_scanned": res["files"], "lines_scanned": res["lines"],
            "languages": db.jdump(res["languages"]), "excluded_files": res["excluded"], "duration_sec": res["duration"],
            "n_critical": cnt["Critical"], "n_high": cnt["High"], "n_medium": cnt["Medium"], "n_low": cnt["Low"],
            "finished_at": db.now()})
        dev = get_device(dev["id"])
        st = device_state(dev)
        if st["assessment"] is None and not db.one("SELECT id FROM assessments WHERE device_id=?", (dev["id"],)):
            # 평가가 하나도 없으면 시스템 평가(미응답, 완료)를 만들어 리포트에 반영한다
            _new_assessment(dev, {}, "시스템", status="완료")
            st = device_state(dev)
        g = st["grade"]
        if g:
            _set_step(scan_id, steps, 6, "done", f"개선관리 지표 {g['final']}, 충족률 {st['result']['rate']}")
            rpt = issue_report(dev, st["assessment"], user)
            _set_step(scan_id, steps, 7, "done", rpt)
        else:
            _set_step(scan_id, steps, 6, "done", "승인된 평가가 없어 승인 때 산출")
            _set_step(scan_id, steps, 7, "skip", "평가 승인 때 발행")
        db.audit(user, "정적분석 완료", f"{dev['name']} v{get_scan_by_id(scan_id)['version']}", "127.0.0.1")
    except Exception as e:  # noqa: BLE001 — 실패 사유를 화면에 보여 준다
        for s in steps:
            if s["state"] in ("run", "wait"):
                s["state"] = "fail" if s["state"] == "run" else "wait"
        db.update("scans", scan_id, {"status": "실패", "error": str(e)[:500], "steps": db.jdump(steps),
                                     "finished_at": db.now()})
        db.audit(user, "정적분석 실패", f"{dev['name']}: {str(e)[:80]}")
    finally:
        if work.exists():
            shutil.rmtree(work, ignore_errors=True)


def get_sbom(scan_id):
    r = db.one("SELECT data FROM sboms WHERE scan_id=?", (scan_id,))
    return db.jload(r["data"], None) if r else None


def latest_sbom(dev_id):
    s = latest_scan(dev_id)
    return (s, get_sbom(s["id"])) if s else (None, None)


def sbom_as_evidence(dev, user):
    """최신 SBOM을 CycloneDX JSON으로 만들어 D08 증빙에 등록한다."""
    s, sb = latest_sbom(dev["id"])
    if not sb:
        return None
    data = json.dumps(sbom.to_cyclonedx(sb, dev, s), ensure_ascii=False, indent=1).encode("utf-8")
    name = f"{dev['code']}_SBOM_CycloneDX-1.5.json"
    save_evidence(dev["id"], "D08", name, data, user)
    return name


def scan_compare(dev_id):
    """기기의 회차별 스캔 비교 (이전 회차 대비 증감)."""
    rows = db.q("SELECT * FROM scans WHERE device_id=? ORDER BY id", (dev_id,))
    prev = None
    for r in rows:
        tot = r["n_critical"] + r["n_high"] + r["n_medium"] + r["n_low"]
        r["total"] = tot
        r["delta"] = None if prev is None else tot - prev
        if r["status"] == "완료":
            prev = tot
    return list(reversed(rows))


# ══ 평가(체크리스트) ════════════════════════════════════════════
def latest_assessment(dev_id):
    return db.one("SELECT * FROM assessments WHERE device_id=? ORDER BY round DESC LIMIT 1", (dev_id,))


def _new_assessment(dev, answers, user, status="작성중"):
    rnd = (db.one("SELECT MAX(round) AS r FROM assessments WHERE device_id=?", (dev["id"],))["r"] or 0) + 1
    res = checklist.score(answers, dev, evidence_slots(dev["id"]))
    code = f"{dev['code']}-ASM-{rnd}"
    db.insert("assessments", {"code": code, "device_id": dev["id"], "round": rnd, "answers": db.jdump(answers),
                              "score": res["rate"], "grade": checklist.base_grade(res["rate"]), "progress": res["progress"],
                              "status": status, "evaluator": user, "created_at": db.now(), "updated_at": db.now()})
    return code


def save_checklist(dev, answers, user):
    """작성중·반려 회차는 고쳐 저장하고, 검토대기·승인 회차가 최신이면 새 회차를 연다."""
    cur = latest_assessment(dev["id"])
    res = checklist.score(answers, dev, evidence_slots(dev["id"]))
    if cur and cur["status"] in ("작성중", "반려"):
        db.update("assessments", cur["id"], {"answers": db.jdump(answers), "score": res["rate"],
                                             "grade": checklist.base_grade(res["rate"]), "progress": res["progress"],
                                             "status": "작성중", "evaluator": user, "updated_at": db.now()})
        return cur["code"], False
    code = _new_assessment(dev, answers, user)
    return code, True


def get_assessment(code):
    return db.one("""SELECT a.*, d.name AS device_name, d.code AS device_code FROM assessments a
                     JOIN devices d ON d.id=a.device_id WHERE a.code=?""", (code,))


def list_assessments():
    return db.q("""SELECT a.*, d.name AS device_name, d.code AS device_code FROM assessments a
                   JOIN devices d ON d.id=a.device_id ORDER BY a.id DESC""")


def assessment_result(asm):
    dev = get_device(asm["device_id"])
    return checklist.score(db.jload(asm["answers"], {}), dev, evidence_slots(dev["id"]))


def request_review(asm, user):
    db.update("assessments", asm["id"], {"status": "검토대기", "requested_by": user, "requested_at": db.now()})


def approve(asm, user, comment=""):
    db.update("assessments", asm["id"], {"status": "승인완료", "reviewer": user, "reviewed_at": db.now(),
                                         "review_comment": comment})
    dev = get_device(asm["device_id"])
    code = issue_report(dev, get_assessment(asm["code"]), user)
    # 최근 스캔이 '평가 승인 시 발행'으로 남아 있으면 처리 단계를 채운다
    scan = db.one("SELECT * FROM scans WHERE device_id=? ORDER BY id DESC LIMIT 1", (dev["id"],))
    if scan and scan["status"] == "완료":
        steps = db.jload(scan["steps"], [])
        if len(steps) == 8 and steps[7]["state"] == "skip":
            st = device_state(dev)
            steps[6].update(state="done", detail=f"개선관리 지표 {st['grade']['final']}, 충족률 {st['result']['rate']} (평가 승인 때 산출)")
            steps[7].update(state="done", detail=f"{code} (평가 승인 때 발행)")
            db.update("scans", scan["id"], {"steps": db.jdump(steps)})
    return code


def reject(asm, user, comment=""):
    db.update("assessments", asm["id"], {"status": "반려", "reviewer": user, "reviewed_at": db.now(),
                                         "review_comment": comment})


def report_for_assessment(asm_id):
    return db.one("SELECT code FROM reports WHERE assessment_id=? ORDER BY id DESC LIMIT 1", (asm_id,))


# ══ 리포트 ═══════════════════════════════════════════════════
def _recommendations(fs):
    groups = {}
    for f in fs:
        g = groups.setdefault(f["rule_id"], {"rule_id": f["rule_id"], "cwe": f["cwe"], "title": f["title"],
                                             "severity": f["severity"], "cvss": f["cvss"], "locs": {}})
        g["locs"].setdefault(f["file"], []).append(f["line"])
    out = []
    for g in groups.values():
        meta = scanner.rule_detail(g["rule_id"])
        g["description"] = meta.get("description_ko", "")
        g["impact_scope"] = meta.get("cvss_vector_note", "")
        g["device_impact"] = meta.get("device_impact_ko", "")
        g["remediation"] = meta.get("remediation_ko", [])
        g["deadline"] = policy.get(f"deadline.{g['severity']}", meta.get("deadline_ko", ""))
        g["fda_ref"] = meta.get("fda_reference_ko", "")
        cached = db.one("SELECT * FROM ai_cache WHERE key=?", (f"rule:{g['rule_id']}",))
        g["ai"] = None
        if cached and not cached["not_found"]:
            g["ai"] = {"answer": cached["answer"], "hits": db.jload(cached["hits"], [])}
        g["locs"] = [{"file": k, "lines": v} for k, v in g["locs"].items()]
        out.append(g)
    return out


def build_snapshot(dev, asm):
    slots_files = evidence_list(dev["id"])
    slots = set(slots_files)
    answers = db.jload(asm["answers"], {}) if asm else {}
    res = checklist.score(answers, dev, slots)
    scan = latest_scan(dev["id"])
    sev = sev_counts(scan) if scan else {}
    grade = checklist.final_grade(res["rate"], sev)
    fs = findings(scan["id"]) if scan else []
    std = standards.evaluate(dev, answers, slots, bool(scan), list(slots_files.values()))
    ev = []
    for code, name, level, qs in checklist.EVIDENCE:
        f = slots_files.get(code)
        ev.append({"code": code, "name": name, "level": level, "qs": qs,
                   "file": {k: f[k] for k in ("filename", "size", "uploaded_at", "version", "sha256")} if f else None})
    sb_sum, sb_vuln = None, []
    if scan:
        sb = get_sbom(scan["id"])
        if sb:
            sb_sum = sbom.summary(sb)
            sb_sum["tools"] = sb.get("tools", [])
            sb_sum["error"] = sb.get("error", "")
            for c in sb["components"]:
                if c.get("vulns"):
                    vs = [sb["vulns"].get(v, {"id": v, "severity": "확인 필요"}) for v in c["vulns"]]
                    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
                    worst = min((order.get(v["severity"], 4) for v in vs), default=4)
                    fixed = next((v.get("fixed", {}).get(c["purl"]) for v in vs if v.get("fixed", {}).get(c["purl"])), "")
                    sb_vuln.append({"name": c["name"], "version": c["version"], "ecosystem": c["ecosystem"], "n": len(vs),
                                    "worst": ["Critical", "High", "Medium", "Low", "확인 필요"][worst], "fixed": fixed,
                                    "ids": [v["id"] for v in vs][:4]})
            sb_vuln.sort(key=lambda x: (["Critical", "High", "Medium", "Low", "확인 필요"].index(x["worst"]), -x["n"]))
        scan = dict(scan, languages=db.jload(scan["languages"], {}))
    return {
        "device": dev, "cyber": checklist.cyber_status(dev), "section524b": checklist.section_524b(dev),
        "assessment": asm, "checklist": res, "grade": grade, "fda": checklist.fda_verdict(dev, res, grade),
        "scan": scan, "sev": sev, "findings": fs, "recs": _recommendations(fs), "evidence": ev,
        "standards": {"rows": [{k: r[k] for k in ("id", "kind", "title", "clause", "duty", "status", "evidence_req")}
                               for r in std["rows"]], "axes": std["axes"], "verdicts": std["verdicts"],
                      "counts": std["counts"]},
        "sbom": sb_sum, "sbom_vuln": sb_vuln[:15],
        "policies": policy.snapshot(),
        "areas": checklist.AREAS,
    }


def issue_report(dev, asm, user):
    n = db.one("SELECT COUNT(*) AS n FROM reports WHERE device_id=?", (dev["id"],))["n"] + 1
    code = f"{dev['code']}-RPT-{n}"
    snap = build_snapshot(dev, asm)
    scan = snap["scan"]
    db.insert("reports", {"code": code, "device_id": dev["id"], "assessment_id": asm["id"] if asm else None,
                          "scan_id": scan["id"] if scan else None, "score": snap["checklist"]["rate"],
                          "grade": snap["grade"]["final"], "status": "발행완료", "snapshot": db.jdump(snap),
                          "issued_by": user, "created_at": db.now()})
    db.audit(user, "리포트 발행", f"{dev['name']} ({code})")
    return code


def list_reports():
    return db.q("""SELECT r.id, r.code, r.kind, r.score, r.grade, r.status, r.created_at, r.device_id,
                          d.name AS device_name, d.code AS device_code
                   FROM reports r JOIN devices d ON d.id=r.device_id ORDER BY r.id DESC""")


def get_report(code):
    r = db.one("SELECT * FROM reports WHERE code=?", (code,))
    if r:
        r["snap"] = db.jload(r["snapshot"], {})
    return r


def revoke_report(code, user):
    db.run("UPDATE reports SET status='폐기', revoked_at=? WHERE code=?", (db.now(), code))
    db.audit(user, "리포트 폐기", code)


# ══ 대시보드 ══════════════════════════════════════════════════
def dashboard():
    devices = db.q("SELECT * FROM devices ORDER BY id DESC")
    latest = []
    for d in devices:
        s = latest_scan(d["id"])
        if s:
            latest.append((d, s))
    sev_total = {k: 0 for k in SEV}
    for _d, s in latest:
        for k, v in sev_counts(s).items():
            sev_total[k] += v
    total_v = sum(sev_total.values())

    def risk_key(item):
        _d, s = item
        return (s["n_critical"], s["n_high"], s["n_medium"], s["n_low"])
    top = sorted(latest, key=risk_key, reverse=True)[:5]
    top_rows = []
    for d, s in top:
        worst = next((k for k in SEV if sev_counts(s)[k]), None)
        top_rows.append({"device": d, "scan": s, "worst": worst})
    # ── 준비도 · FDA 적합성 · 처분 · 기기 구조 분석 (대시보드 개편)
    states = [(d, device_state(d)) for d in devices]
    fda_cnt = {k: sum(1 for _d, st in states if st["fda"] == k) for k in ("적합", "조건부 적합", "부적합", "판정 불가")}
    approved = [st for _d, st in states if st["assessment"] and st["assessment"]["status"] == "승인완료" and st["result"]]
    avg_rate = round(sum(st["result"]["rate"] for st in approved) / len(approved), 1) if approved else None
    latest_ids = [s["id"] for _d, s in latest]
    disp = {k: 0 for k in ("확인된 결함", "약점", "오탐", "연기", "검토 필요")}
    if latest_ids:
        marks = ",".join("?" * len(latest_ids))
        for r in db.q(f"SELECT disposition, COUNT(*) AS n FROM findings WHERE scan_id IN ({marks}) GROUP BY disposition", tuple(latest_ids)):
            disp[r["disposition"] or "검토 필요"] = disp.get(r["disposition"] or "검토 필요", 0) + r["n"]
    n_done = sum(v for k, v in disp.items() if k != "검토 필요")
    rows = []
    for d, st in states:
        s = st["scan"]
        tot = done = 0
        if s:
            c = db.one("SELECT COUNT(*) AS t, SUM(CASE WHEN disposition IS NOT NULL AND disposition!='검토 필요' THEN 1 ELSE 0 END) AS d "
                       "FROM findings WHERE scan_id=?", (s["id"],))
            tot, done = c["t"] or 0, c["d"] or 0
        g = st["grade"]
        hi = (st["sev"] or {}).get("Critical", 0) + (st["sev"] or {}).get("High", 0)
        if not s:
            nxt = ("소스 업로드", f"/devices/{d['code']}?tab=evidence")
        elif not st["assessment"]:
            nxt = ("체크리스트 작성", f"/devices/{d['code']}?tab=checklist")
        elif done < tot:
            nxt = (f"검출 {tot - done}건 처분 기록", f"/scans/{s['code']}")
        elif hi:
            nxt = (f"High {hi}건 조치 후 재업로드", f"/devices/{d['code']}?tab=evidence")
        else:
            nxt = ("리포트 확인", "/reports")
        rows.append({"device": d, "fda": st["fda"], "rate": st["result"]["rate"] if st["result"] else None,
                     "final": g["final"] if g else None, "base": g["base"] if g else None,
                     "capped": bool(g and g["cap"] and g["final"] != g["base"]), "tot": tot, "done": done, "next": nxt,
                     "approved": bool(st["assessment"] and st["assessment"]["status"] == "승인완료")})
    rows.sort(key=lambda r: (not r["approved"], r["rate"] is None, -(r["rate"] or 0)))
    return {
        "n_devices": len(devices),
        "n_scans_done": db.one("SELECT COUNT(*) AS n FROM scans WHERE status='완료'")["n"],
        "n_vulns": total_v,
        "n_assess_open": db.one("SELECT COUNT(*) AS n FROM assessments WHERE status IN ('작성중','검토대기')")["n"],
        "sev_total": sev_total,
        "top": top_rows,
        "recent": list_scans(limit=5),
        "n_scans": db.one("SELECT COUNT(*) AS n FROM scans")["n"],
        "fda_cnt": fda_cnt, "avg_rate": avg_rate, "n_approved": len(approved),
        "approved": [{"name": d["name"], "rate": st["result"]["rate"], "base": st["grade"]["base"], "final": st["grade"]["final"]}
                     for d, st in states if st in approved],
        "lines": sum((s["lines_scanned"] or 0) for _d, s in latest),
        "disp": disp, "n_done": n_done, "rows": rows,
        "activity": db.q("SELECT at, user, action, target FROM audit_logs WHERE action != '로그인' ORDER BY id DESC LIMIT 5"),
        "device_view": device_view(latest),
    }


# 기기 구조 분석: 소스 파일 → 탑재 부품 (SecPump 계열 STM32 펌웨어 기준)
PART_MAP = {
    "PumpService.c": ("mcu", "MCU 펌프 서비스", "BLE 명령 처리 · STM32F4"),
    "InsulinController.c": ("motor", "인슐린 주입 제어", "주입량 계산 · 모터 구동"),
    "app_x-cube-ble1.c": ("ble", "BLE 무선 모듈", "무선 수신 · X-CUBE-BLE1"),
}


def device_view(latest):
    """부품에 매핑되는 검출이 가장 많은 기기 하나를 골라 부품별 검출을 묶는다."""
    best = None
    for d, s in latest:
        fs = db.q("SELECT file, line, cwe, severity, disposition FROM findings WHERE scan_id=? ORDER BY line", (s["id"],))
        hit = [f for f in fs if f["file"].rsplit("/", 1)[-1] in PART_MAP]
        if hit and (best is None or (len(hit), -d["id"]) > (len(best[2]), -best[0]["id"])):
            best = (d, s, hit)
    if not best:
        return None
    d, s, hit = best
    parts = {}
    for f in hit:
        key, name, role = PART_MAP[f["file"].rsplit("/", 1)[-1]]
        p = parts.setdefault(key, {"key": key, "name": name, "role": role, "file": f["file"].rsplit("/", 1)[-1], "finds": []})
        p["finds"].append(f)
    sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    for p in parts.values():
        open_items = [f for f in p["finds"] if f["disposition"] != "오탐"]
        p["worst"] = min((f["severity"] for f in open_items), key=lambda x: sev_rank.get(x, 9)) if open_items else None
        p["level"] = "high" if p["worst"] in ("Critical", "High") else ("med" if p["worst"] else "fp")
        cwes = {}
        for f in p["finds"]:
            cwes.setdefault((f["cwe"], f["severity"]), 0)
            cwes[(f["cwe"], f["severity"])] += 1
        p["summary"] = " · ".join(f"{c} {sv} {n}" for (c, sv), n in cwes.items())
        p["notes"] = ", ".join(f"{f['line']}행 {f['disposition'] or '검토 필요'}" for f in p["finds"])
    order = [k for k in ("mcu", "motor", "ble") if k in parts]
    return {"device": d, "scan": s, "parts": [parts[k] for k in order], "n": len(hit)}
