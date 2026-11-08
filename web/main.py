"""메디가이드 웹 서버 (FastAPI + Jinja2).

실행:  python -m uvicorn web.main:app --port 8501
"""
import csv
import io
import json
import os
import sys
import tempfile
import threading
import zipfile
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi import FastAPI, File, Form, Request, UploadFile  # noqa: E402
from fastapi.responses import (FileResponse, HTMLResponse, JSONResponse, PlainTextResponse,  # noqa: E402
                               RedirectResponse, Response, StreamingResponse)
from fastapi.staticfiles import StaticFiles  # noqa: E402
from fastapi.templating import Jinja2Templates  # noqa: E402
from starlette.middleware.sessions import SessionMiddleware  # noqa: E402

from core import checklist, config, db, policy, scanner, service, standards  # noqa: E402
from core import forms as jforms  # noqa: E402
from core import pdf as pdfmod  # noqa: E402
from web.icons import icon  # noqa: E402

VERSION = "1.0"
WEB = Path(__file__).resolve().parent

app = FastAPI(title="메디가이드", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=WEB / "static"), name="static")
T = Jinja2Templates(directory=WEB / "templates")
T.env.globals.update(icon=icon, ver=VERSION, checklist=checklist, standards=standards, jload=db.jload)
T.env.filters["num"] = lambda v: f"{v:,}" if isinstance(v, (int, float)) else v
T.env.filters["kb"] = lambda v: f"{(v or 0) / 1024:,.1f} KB" if (v or 0) < 1024 * 1024 else f"{v / 1024 / 1024:,.1f} MB"


def fmt_score(v):
    if v is None:
        return "—"
    return f"{v:g}" if isinstance(v, (int, float)) else str(v)


T.env.filters["sc"] = fmt_score


def cite(text):
    import re
    from markupsafe import Markup, escape
    return Markup(re.sub(r"\[(\d+)\]", r'<span class="cite">\1</span>', str(escape(text or ""))))


T.env.filters["cite"] = cite


@app.on_event("startup")
def _startup():
    db.init_db()
    policy.seed()
    if not db.one("SELECT id FROM users LIMIT 1"):
        service.create_user("admin", os.getenv("MG_ADMIN_PASSWORD", "medi1234!"), "관리자", "admin@mediguide.local", "8팀 무한루프")
        service.create_user("verifier", os.getenv("MG_VERIFIER_PASSWORD", "verify1234!"), "검증자",
                            "verifier@mediguide.local", "8팀 무한루프")
    # 첫 질문 대기를 줄이려고 로컬 AI 모델을 미리 올린다
    from core import llm
    threading.Thread(target=llm.warm_up, daemon=True).start()


# ── 공통 ─────────────────────────────────────────────────────
def ip(req: Request):
    return req.client.host if req.client else ""


def cur_user(req: Request):
    uid = req.session.get("uid")
    if not uid:
        return None
    return db.one("SELECT id, username, email, role, org FROM users WHERE id=? AND active=1", (uid,))


def flash(req: Request, kind, msg):
    req.session.setdefault("flash", []).append([kind, msg])


def render(req: Request, name, ctx=None, code=200):
    ctx = dict(ctx or {})
    ctx.setdefault("user", cur_user(req))
    ctx["flashes"] = req.session.pop("flash", [])
    ctx["request"] = req
    return T.TemplateResponse(req, name, ctx, status_code=code)


def back(url):
    return RedirectResponse(url, status_code=303)


PUBLIC = ("/login", "/static", "/healthz")


@app.middleware("http")
async def auth_guard(request: Request, call_next):
    path = request.url.path
    if not path.startswith(PUBLIC) and not request.session.get("uid"):
        if path.startswith("/api/"):
            return JSONResponse({"error": "로그인이 필요합니다."}, status_code=401)
        return RedirectResponse("/login", status_code=303)
    return await call_next(request)


# 세션 미들웨어는 마지막에 추가해야 가장 바깥에서 먼저 실행된다(위 auth_guard가 세션을 읽음)
app.add_middleware(SessionMiddleware, secret_key=os.getenv("MG_SECRET", "mediguide-dev-secret-change-me"),
                   session_cookie="mg_session", max_age=60 * 60 * 12)


def can_edit(u):
    return u and u["role"] in ("관리자", "검증자")


def can_review(u):
    return u and u["role"] in ("관리자", "검증자")


def is_admin(u):
    return u and u["role"] == "관리자"


def deny(req, url):
    flash(req, "err", "권한이 없습니다.")
    return back(url)


@app.get("/healthz")
def healthz():
    return {"ok": True}


# ── 로그인 ───────────────────────────────────────────────────
@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return T.TemplateResponse(request, "login.html", {"request": request, "error": None})


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    u = service.authenticate(username.strip(), password)
    if not u:
        db.audit(username, "로그인 실패", "", ip(request))
        return T.TemplateResponse(request, "login.html", {"request": request, "error": "아이디 또는 비밀번호가 올바르지 않습니다."},
                                  status_code=401)
    request.session["uid"] = u["id"]
    db.audit(u["username"], "로그인", "", ip(request))
    return back("/dashboard")


@app.get("/logout")
def logout(request: Request):
    u = cur_user(request)
    if u:
        db.audit(u["username"], "로그아웃", "", ip(request))
    request.session.clear()
    return back("/login")


@app.get("/")
def root():
    return back("/dashboard")


# ── 대시보드 ─────────────────────────────────────────────────
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    return render(request, "dashboard.html", {"d": service.dashboard()})


# ── 의료기기 ─────────────────────────────────────────────────
@app.get("/devices", response_class=HTMLResponse)
def devices(request: Request):
    rows = service.list_devices_full()
    cnt = {k: sum(1 for r in rows if r["fda"] == k) for k in ("적합", "조건부 적합", "부적합", "해당 없음", "판정 불가")}
    return render(request, "devices.html", {"rows": rows, "cnt": cnt})


def _tri(v):
    return None if v in (None, "") else int(v)


@app.post("/devices")
async def device_create(request: Request):
    u = cur_user(request)
    if not can_edit(u):
        return deny(request, "/devices")
    f = await request.form()
    data = {k: (f.get(k) or "").strip() for k in ("name", "name_en", "model", "maker", "maker_en", "device_class", "sw_version", "fw_version",
                                                   "description", "target_market", "submission_path")}
    if not data["name"]:
        flash(request, "err", "기기명을 입력하세요.")
        return back("/devices")
    data.update(is_modification=_tri(f.get("is_modification")) or 0, has_software=_tri(f.get("has_software")),
                internet=_tri(f.get("internet")), vuln_tech=_tri(f.get("vuln_tech")))
    _id, code = service.add_device(data, u["username"])
    db.audit(u["username"], "기기 등록", f"{data['name']} ({code})", ip(request))
    flash(request, "ok", f"{code} 「{data['name']}」을(를) 등록했습니다. 증빙 자료 탭에서 소스코드를 올리면 정적분석이 시작됩니다.")
    return back(f"/devices/{code}?tab=evidence")


TABS = [("info", "기본 정보"), ("scans", "스캔 결과"), ("evidence", "증빙 자료"), ("checklist", "체크리스트"),
        ("standards", "표준화"), ("sbom", "SBOM")]


@app.get("/devices/{code}", response_class=HTMLResponse)
def device_detail(request: Request, code: str, tab: str = "info", req: str = "", j: str = ""):
    dev = service.get_device_by_code(code)
    if not dev:
        return render(request, "error.html", {"msg": "기기를 찾을 수 없습니다."}, 404)
    st = service.device_state(dev)
    ev = service.evidence_list(dev["id"])
    slots = set(ev)
    ctx = {"dev": dev, "st": st, "tab": tab, "tabs": TABS, "ev": ev, "cyber": checklist.cyber_status(dev),
           "s524b": checklist.section_524b(dev), "fda_paths": checklist.fda_paths()}
    latest = service.latest_assessment(dev["id"])
    answers = db.jload(latest["answers"], {}) if latest else {}
    if tab == "info":
        asms = db.q("SELECT * FROM assessments WHERE device_id=? ORDER BY round DESC", (dev["id"],))
        for a in asms:
            rp = service.report_for_assessment(a["id"])
            a["report"] = rp["code"] if rp else None
        ctx.update(asms=asms, history=service.device_history(dev["id"]))
    elif tab == "scans":
        scans = service.scan_compare(dev["id"])
        for s in scans:
            rp = db.one("SELECT code, grade FROM reports WHERE scan_id=? AND status='발행완료' ORDER BY id DESC LIMIT 1", (s["id"],))
            s["report"] = rp
        ctx.update(scans=scans)
    elif tab == "evidence":
        last = db.one("SELECT * FROM scans WHERE device_id=? ORDER BY id DESC LIMIT 1", (dev["id"],))
        if last:
            last = dict(last, steps_l=db.jload(last["steps"], []), langs=db.jload(last["languages"], {}))
        missing = [e for e in checklist.EVIDENCE if e[2] in ("법정", "필수") and e[0] not in slots]
        ctx.update(last=last, missing=missing, evdefs=checklist.EVIDENCE)
    elif tab == "checklist":
        res = checklist.score(answers, dev, slots)
        grade = checklist.final_grade(res["rate"], st["sev"])
        scan_done = service.latest_scan(dev["id"])
        ctx.update(latest=latest, answers=answers, res=res, gr=grade, scan_done=scan_done)
    elif tab == "standards":
        std = standards.evaluate(dev, answers, slots, bool(st["scan"]), list(ev.values()))
        pick = next((r for r in std["rows"] if r["id"] == req), std["rows"][0])
        ctx.update(std=std, pick=pick, juris=j or dev.get("target_market") or "미국 FDA")
    return render(request, "device_detail.html", ctx)


@app.post("/devices/{code}/edit")
async def device_edit(request: Request, code: str):
    u = cur_user(request)
    if not can_edit(u):
        return deny(request, f"/devices/{code}")
    dev = service.get_device_by_code(code)
    f = await request.form()
    data = {k: (f.get(k) or "").strip() for k in ("name", "name_en", "model", "maker", "maker_en", "device_class", "sw_version", "fw_version", "description")}
    ch = service.update_device(dev["id"], data, u["username"])
    if ch:
        db.audit(u["username"], "기기 정보 수정", f"{dev['name']} ({code})", ip(request))
    flash(request, "ok", "장비 정보를 저장했습니다." if ch else "바뀐 내용이 없습니다.")
    return back(f"/devices/{code}?tab=info")


@app.post("/devices/{code}/submission")
async def device_submission(request: Request, code: str):
    u = cur_user(request)
    if not can_edit(u):
        return deny(request, f"/devices/{code}")
    dev = service.get_device_by_code(code)
    f = await request.form()
    data = {"target_market": f.get("target_market"), "submission_path": f.get("submission_path"),
            "is_modification": _tri(f.get("is_modification")) or 0, "has_software": _tri(f.get("has_software")),
            "internet": _tri(f.get("internet")), "vuln_tech": _tri(f.get("vuln_tech"))}
    ch = service.update_device(dev["id"], data, u["username"])
    if ch:
        db.audit(u["username"], "제출 정보 수정", f"{dev['name']} ({code})", ip(request))
    flash(request, "ok", "제출 정보·사이버 기기 판정을 저장했습니다.")
    return back(f"/devices/{code}?tab=info")


@app.post("/devices/{code}/upload-source")
async def upload_source(request: Request, code: str, file: UploadFile = File(...), version: str = Form("")):
    u = cur_user(request)
    if not can_edit(u):
        return deny(request, f"/devices/{code}?tab=evidence")
    dev = service.get_device_by_code(code)
    name = Path(file.filename or "source.zip").name
    if not name.lower().endswith((".zip", ".tar.gz", ".tgz")):
        flash(request, "err", "지원 형식은 .zip · .tar.gz · .tgz 입니다.")
        return back(f"/devices/{code}?tab=evidence")
    dest = config.UPLOADS / "sources" / code
    dest.mkdir(parents=True, exist_ok=True)
    path = dest / name
    with open(path, "wb") as out:
        while chunk := await file.read(1 << 20):
            out.write(chunk)
    db.audit(u["username"], "증빙 자료 업로드", f"{dev['name']} / {name}", ip(request))
    scode = service.start_scan(dev, path, name, version.strip() or dev.get("sw_version"), u["username"])
    flash(request, "ok", f"{scode} 정적분석을 시작했습니다.")
    return back(f"/devices/{code}?tab=evidence")


@app.post("/devices/{code}/evidence/{slot}")
async def upload_evidence(request: Request, code: str, slot: str, file: UploadFile = File(...)):
    u = cur_user(request)
    if not can_edit(u):
        return deny(request, f"/devices/{code}?tab=evidence")
    dev = service.get_device_by_code(code)
    data = await file.read()
    max_mb = float(policy.get("evidence.max_mb", "50"))
    if len(data) > max_mb * 1024 * 1024:
        flash(request, "err", f"파일이 너무 큽니다 (최대 {max_mb:g}MB).")
        return back(f"/devices/{code}?tab=evidence")
    service.save_evidence(dev["id"], slot, file.filename or "file", data, u["username"])
    db.audit(u["username"], "증빙 자료 업로드", f"{dev['name']} / {slot} {file.filename}", ip(request))
    flash(request, "ok", f"{slot} 증빙을 올렸습니다.")
    return back(f"/devices/{code}?tab=evidence")


@app.post("/devices/{code}/evidence/{slot}/delete")
def delete_evidence(request: Request, code: str, slot: str):
    u = cur_user(request)
    if not can_edit(u):
        return deny(request, f"/devices/{code}?tab=evidence")
    dev = service.get_device_by_code(code)
    service.delete_evidence(dev["id"], slot)
    db.audit(u["username"], "증빙 자료 삭제", f"{dev['name']} / {slot}", ip(request))
    return back(f"/devices/{code}?tab=evidence")


@app.get("/evidence/{eid}")
def download_evidence(eid: int):
    r = db.one("SELECT * FROM evidence WHERE id=?", (eid,))
    if not r or not Path(r["stored"]).exists():
        return PlainTextResponse("파일이 없습니다.", status_code=404)
    return FileResponse(r["stored"], filename=r["filename"])


@app.post("/devices/{code}/checklist")
async def save_checklist(request: Request, code: str):
    u = cur_user(request)
    if not can_edit(u):
        return deny(request, f"/devices/{code}?tab=checklist")
    dev = service.get_device_by_code(code)
    f = await request.form()
    answers = {qid: f.get(qid) for qid in checklist.Q if f.get(qid)}
    acode, new = service.save_checklist(dev, answers, u["username"])
    db.audit(u["username"], "체크리스트 저장", f"{dev['name']} ({acode})", ip(request))
    if f.get("then") == "request":
        service.request_review(service.get_assessment(acode), u["username"])
        db.audit(u["username"], "검토 요청", acode, ip(request))
        flash(request, "ok", f"{acode} 검토를 요청했습니다. 검증자가 승인하면 리포트가 발행됩니다.")
    else:
        flash(request, "ok", f"{acode} {'새 회차를 열어 ' if new else ''}저장했습니다.")
    return back(f"/devices/{code}?tab=checklist")


@app.post("/devices/{code}/standards/{rid}")
async def save_std(request: Request, code: str, rid: str):
    u = cur_user(request)
    if not can_edit(u):
        return deny(request, f"/devices/{code}?tab=standards&req={rid}")
    dev = service.get_device_by_code(code)
    f = await request.form()
    standards.set_status(dev["id"], rid, f.get("status") or None, f.get("memo") or "", u["username"])
    db.audit(u["username"], "표준화 평가상태 변경", f"{dev['name']} / {rid} → {f.get('status') or '자동'}", ip(request))
    return back(f"/devices/{code}?tab=standards&req={rid}")


@app.get("/devices/{code}/package")
def submission_package(request: Request, code: str):
    """제출 패키지: 최신 리포트(HTML·PDF), 관할별 결과보고서, 증빙 파일, 취약점 목록(CSV)."""
    dev = service.get_device_by_code(code)
    rpt = db.one("SELECT code FROM reports WHERE device_id=? AND status='발행완료' ORDER BY id DESC LIMIT 1", (dev["id"],))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        if rpt:
            r = service.get_report(rpt["code"])
            html = _report_html(request, r)
            z.writestr(f"01_리포트/{r['code']}_보안성검증리포트.html", html)
            pdf = pdfmod.html_to_pdf(html)
            if pdf:
                z.writestr(f"01_리포트/{r['code']}_보안성검증리포트.pdf", pdf)
            for kind in jforms.KINDS:
                fh = jforms.render(T, r, kind)
                z.writestr(f"02_관할별_결과보고서/{jforms.KINDS[kind]['file']}.html", fh)
        for slot, e in service.evidence_list(dev["id"]).items():
            if Path(e["stored"]).exists():
                z.write(e["stored"], f"03_증빙/{slot}_{e['filename']}")
        s = service.latest_scan(dev["id"])
        if s:
            out = io.StringIO()
            w = csv.writer(out)
            w.writerow(["CWE", "취약점명", "심각도", "파일", "라인", "룰 ID", "처분", "평가 심각도", "근거", "조치"])
            for f in service.findings(s["id"]):
                w.writerow([f["cwe"], f["title"], f["severity"], f["file"], f["line"], f["rule_id"], f["disposition"],
                            f["assessed_severity"] or "", f["rationale"] or "", f["action"] or ""])
            z.writestr(f"04_정적분석/{s['code']}_취약점목록.csv", "﻿" + out.getvalue())
    u = cur_user(request)
    db.audit(u["username"], "제출 패키지 내려받기", f"{dev['name']} ({code})", ip(request))
    fname = quote(f"{code}_제출패키지.zip")
    return Response(buf.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition": f"attachment; filename*=UTF-8''{fname}"})


# ── 정적분석 ─────────────────────────────────────────────────
@app.get("/scans", response_class=HTMLResponse)
def scans(request: Request):
    rows = service.list_scans()
    cnt = {"Critical": sum(1 for r in rows if r["n_critical"]), "High": sum(1 for r in rows if r["n_high"]),
           "Medium": sum(1 for r in rows if r["n_medium"]), "Low": sum(1 for r in rows if r["n_low"]),
           "other": sum(1 for r in rows if r["n_other"])}
    return render(request, "scans.html", {"rows": rows, "cnt": cnt})


@app.get("/scans/{code}", response_class=HTMLResponse)
def scan_detail(request: Request, code: str, frm: str = ""):
    s = service.get_scan(code)
    if not s:
        return render(request, "error.html", {"msg": "스캔을 찾을 수 없습니다."}, 404)
    fs = service.findings(s["id"])
    return render(request, "scan_detail.html", {"s": s, "fs": fs, "langs": db.jload(s["languages"], {})})


@app.get("/api/scans/{code}/steps")
def scan_steps(request: Request, code: str):
    s = service.get_scan(code)
    html = T.get_template("_steps.html").render(s=dict(s, steps_l=db.jload(s["steps"], [])), icon=icon)
    return {"status": s["status"], "html": html}


@app.get("/api/findings/{fid}", response_class=HTMLResponse)
def finding_modal(request: Request, fid: int):
    f = service.get_finding(fid)
    meta = scanner.rule_detail(f["rule_id"])
    cached = db.one("SELECT * FROM ai_cache WHERE key=?", (f"rule:{f['rule_id']}",))
    return T.TemplateResponse(request, "_finding.html", {"request": request, "f": f, "meta": meta, "user": cur_user(request),
                                                          "cached": cached, "hits": db.jload(cached["hits"], []) if cached else []})


@app.post("/findings/{fid}/triage")
async def triage(request: Request, fid: int):
    u = cur_user(request)
    f = service.get_finding(fid)
    s = service.get_scan_by_id(f["scan_id"])
    if not can_edit(u):
        return deny(request, f"/scans/{s['code']}")
    fm = await request.form()
    service.triage(fid, fm.get("disposition"), fm.get("assessed_severity"), fm.get("rationale", "").strip(),
                   fm.get("action", "").strip(), u["username"])
    db.audit(u["username"], "검출 처분 기록", f"{s['code']} {f['file']}:{f['line']} → {fm.get('disposition')}", ip(request))
    flash(request, "ok", f"{f['file']}:{f['line']} 처분을 「{fm.get('disposition')}」(으)로 기록했습니다.")
    return back(f"/scans/{s['code']}")


# ── 평가 관리 ────────────────────────────────────────────────
@app.get("/assessments", response_class=HTMLResponse)
def assessments(request: Request):
    rows = service.list_assessments()
    cnt = {k: sum(1 for r in rows if r["status"] == k) for k in ("작성중", "검토대기", "승인완료", "반려", "완료")}
    return render(request, "assessments.html", {"rows": rows, "cnt": cnt})


@app.get("/api/assessments/{code}", response_class=HTMLResponse)
def assessment_modal(request: Request, code: str):
    a = service.get_assessment(code)
    res = service.assessment_result(a)
    rp = service.report_for_assessment(a["id"])
    return T.TemplateResponse(request, "_assessment.html", {"request": request, "a": a, "res": res, "report": rp,
                                                             "user": cur_user(request),
                                                             "grade": checklist.base_grade(res["rate"])})


@app.post("/assessments/{code}/{action}")
async def assessment_action(request: Request, code: str, action: str):
    u = cur_user(request)
    a = service.get_assessment(code)
    f = await request.form()
    comment = (f.get("comment") or "").strip()
    nxt = f.get("next") or "/assessments"
    if action == "request" and can_edit(u) and a["status"] in ("작성중", "반려"):
        service.request_review(a, u["username"])
        db.audit(u["username"], "검토 요청", code, ip(request))
        flash(request, "ok", f"{code} 검토를 요청했습니다.")
    elif action == "approve" and can_review(u) and a["status"] == "검토대기":
        rpt = service.approve(a, u["username"], comment)
        db.audit(u["username"], "평가 승인", code, ip(request))
        flash(request, "ok", f"{code}을(를) 승인하고 리포트 {rpt}을(를) 발행했습니다.")
    elif action == "reject" and can_review(u) and a["status"] == "검토대기":
        service.reject(a, u["username"], comment)
        db.audit(u["username"], "평가 반려", code, ip(request))
        flash(request, "ok", f"{code}을(를) 반려했습니다.")
    else:
        flash(request, "err", "지금 상태에서는 할 수 없는 작업이거나 권한이 없습니다.")
    return back(nxt)


# ── 리포트 ───────────────────────────────────────────────────
@app.get("/reports", response_class=HTMLResponse)
def reports(request: Request):
    rows = service.list_reports()
    cnt = {g: sum(1 for r in rows if r["grade"] == g and r["status"] != "폐기") for g in "ABCD"}
    cnt["폐기"] = sum(1 for r in rows if r["status"] == "폐기")
    return render(request, "reports.html", {"rows": rows, "cnt": cnt})


@app.get("/reports/{code}", response_class=HTMLResponse)
def report_detail(request: Request, code: str):
    r = service.get_report(code)
    if not r:
        return render(request, "error.html", {"msg": "리포트를 찾을 수 없습니다."}, 404)
    return render(request, "report_detail.html", {"r": r, "s": r["snap"], "kinds": jforms.KINDS})


def _report_html(request, r):
    css = (WEB / "static" / "doc.css").read_text(encoding="utf-8")
    return T.get_template("report_print.html").render(r=r, s=r["snap"], css=css, icon=icon, ver=VERSION)


@app.get("/reports/{code}/print", response_class=HTMLResponse)
def report_print(request: Request, code: str):
    return HTMLResponse(_report_html(request, service.get_report(code)))


@app.get("/reports/{code}/pdf")
def report_pdf(request: Request, code: str):
    r = service.get_report(code)
    pdf = pdfmod.html_to_pdf(_report_html(request, r))
    u = cur_user(request)
    db.audit(u["username"], "리포트 PDF 다운로드", code, ip(request))
    if not pdf:
        flash(request, "err", "서버에 PDF 변환용 브라우저(Chrome/Chromium)가 없어 인쇄 화면을 엽니다. 「PDF로 저장」을 선택하세요.")
        return back(f"/reports/{code}/print?autoprint=1")
    fname = quote(f"{code}_보안성검증리포트.pdf")
    return Response(pdf, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename*=UTF-8''{fname}"})


@app.get("/reports/{code}/forms/{kind}", response_class=HTMLResponse)
def report_form(request: Request, code: str, kind: str, pdf: int = 0):
    r = service.get_report(code)
    html = jforms.render(T, r, kind)
    if pdf:
        data = pdfmod.html_to_pdf(html)
        if data:
            fname = quote(f"{jforms.KINDS[kind]['file']}_{code}.pdf")
            return Response(data, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename*=UTF-8''{fname}"})
    return HTMLResponse(html)


@app.post("/reports/{code}/reissue")
def report_reissue(request: Request, code: str):
    u = cur_user(request)
    if not can_edit(u):
        return deny(request, f"/reports/{code}")
    r = service.get_report(code)
    dev = service.get_device(r["device_id"])
    asm = db.one("SELECT * FROM assessments WHERE id=?", (r["assessment_id"],)) if r["assessment_id"] else None
    new = service.issue_report(dev, asm, u["username"])
    flash(request, "ok", f"최신 기기 정보·스캔·증빙으로 {new}을(를) 재발행했습니다.")
    return back(f"/reports/{new}")


@app.post("/reports/{code}/revoke")
def report_revoke(request: Request, code: str):
    u = cur_user(request)
    if not can_review(u):
        return deny(request, f"/reports/{code}")
    service.revoke_report(code, u["username"])
    flash(request, "ok", f"{code}을(를) 폐기했습니다.")
    return back(f"/reports/{code}")


# ── AI 매뉴얼 ────────────────────────────────────────────────
@app.get("/manual", response_class=HTMLResponse)
def manual(request: Request):
    from core import llm, rag
    return render(request, "manual.html", {"ai_label": llm.provider_label(), "ai_ok": llm.available(), "index": rag.index_info()})


def _ai_stream(question, org=None, expand=False, cache_key=None, extra=()):
    from core import llm, rag

    def gen():
        try:
            k = int(policy.get("ai.top_k", "5"))
            per = int(policy.get("ai.per_doc", "2"))
            ex = list(extra)
            if expand and org != "식약처":
                en = llm.expand_query_en(question)
                if en:
                    ex.append(en)
            hits = rag.search(question, k=k, org=org, extra_queries=tuple(ex), per_doc=per)
            slim = [{"org": h["org"], "title": h["title"], "page": h["page"], "text": h["text"][:700]} for h in hits]
            yield json.dumps({"hits": slim}, ensure_ascii=False) + "\n"
            if not llm.available():
                yield json.dumps({"final": "AI 답변 생성이 꺼져 있어 근거 원문만 보여 드립니다. (시스템 설정에서 AI 상태 확인)",
                                  "not_found": True}, ensure_ascii=False) + "\n"
                return
            text = ""
            for piece in llm.answer_stream(question, hits):
                text += piece
                yield json.dumps({"d": piece}, ensure_ascii=False) + "\n"
            final, nf = llm.finalize(text, hits)
            if cache_key:
                db.run("INSERT OR REPLACE INTO ai_cache(key, answer, hits, not_found, at) VALUES(?,?,?,?,?)",
                       (cache_key, final, db.jdump(slim), int(nf), db.now()))
            yield json.dumps({"final": final, "not_found": nf}, ensure_ascii=False) + "\n"
        except Exception as e:  # noqa: BLE001
            yield json.dumps({"error": f"오류: {e}"}, ensure_ascii=False) + "\n"
    return StreamingResponse(gen(), media_type="application/x-ndjson")


@app.post("/api/ai/ask")
async def ai_ask(request: Request):
    body = await request.json()
    q = (body.get("q") or "").strip()
    if not q:
        return JSONResponse({"error": "질문을 입력하세요."}, status_code=400)
    u = cur_user(request)
    db.audit(u["username"], "AI 매뉴얼 검색", q[:80], ip(request))
    org = body.get("org") or None
    return _ai_stream(q, org=org if org in ("식약처", "FDA") else None, expand=bool(body.get("expand")))


@app.post("/api/ai/finding/{fid}")
def ai_finding(request: Request, fid: int):
    f = service.get_finding(fid)
    meta = scanner.rule_detail(f["rule_id"])
    name = meta.get("name_ko") or f["title"]
    q = f"의료기기 소프트웨어에서 {f['cwe']} {name} 취약점이 발견되었을 때 인허가 제출 전 조치와 제출해야 할 자료는 무엇인가?"
    extra = (f"{f['cwe']} {meta.get('name_en', '')} vulnerability remediation premarket cybersecurity",)
    u = cur_user(request)
    db.audit(u["username"], "AI 조치 매뉴얼", f"{f['cwe']} {f['file']}:{f['line']}", ip(request))
    return _ai_stream(q, cache_key=f"rule:{f['rule_id']}", extra=extra)


# ── 관리자 ───────────────────────────────────────────────────
@app.get("/admin", response_class=HTMLResponse)
def admin_users(request: Request):
    rows = service.list_users()
    cnt = {k: sum(1 for r in rows if r["role"] == k) for k in ("관리자", "검증자", "열람자")}
    return render(request, "admin_users.html", {"rows": rows, "cnt": cnt})


@app.post("/admin/users")
async def admin_user_add(request: Request):
    u = cur_user(request)
    if not is_admin(u):
        return deny(request, "/admin")
    f = await request.form()
    name, pw = (f.get("username") or "").strip(), f.get("password") or ""
    if not name or len(pw) < 8:
        flash(request, "err", "사용자명과 8자 이상 비밀번호를 입력하세요.")
        return back("/admin")
    if db.one("SELECT id FROM users WHERE username=?", (name,)):
        flash(request, "err", "이미 있는 사용자명입니다.")
        return back("/admin")
    service.create_user(name, pw, f.get("role") or "열람자", f.get("email") or "", f.get("org") or "", f.get("phone") or "")
    db.audit(u["username"], "사용자 추가", f"{name} ({f.get('role')})", ip(request))
    flash(request, "ok", f"사용자 {name}을(를) 추가했습니다.")
    return back("/admin")


@app.post("/admin/users/{uid}")
async def admin_user_edit(request: Request, uid: int):
    u = cur_user(request)
    if not is_admin(u):
        return deny(request, "/admin")
    f = await request.form()
    target = db.one("SELECT * FROM users WHERE id=?", (uid,))
    data = {}
    if f.get("role"):
        data["role"] = f.get("role")
    if f.get("active") is not None:
        if uid == u["id"] and f.get("active") == "0":
            flash(request, "err", "자기 계정은 비활성화할 수 없습니다.")
            return back("/admin")
        data["active"] = int(f.get("active"))
    if f.get("password"):
        if len(f.get("password")) < 8:
            flash(request, "err", "비밀번호는 8자 이상이어야 합니다.")
            return back("/admin")
        data["pw_hash"] = service.hash_pw(f.get("password"))
    for k in ("email", "org", "phone"):
        if f.get(k) is not None:
            data[k] = f.get(k)
    db.update("users", uid, data)
    db.audit(u["username"], "사용자 수정", target["username"], ip(request))
    flash(request, "ok", f"{target['username']} 정보를 저장했습니다.")
    return back("/admin")


@app.get("/admin/audit-logs", response_class=HTMLResponse)
def admin_audit(request: Request, start: str = "", end: str = "", action: str = "", logins: int = 0):
    rows, actions = _audit_rows(start, end, action, logins)
    return render(request, "admin_audit.html", {"rows": rows, "actions": actions, "start": start, "end": end,
                                                "action": action, "logins": logins})


def _audit_rows(start, end, action, logins):
    sql, args = "SELECT * FROM audit_logs WHERE 1=1", []
    if start:
        sql += " AND at >= ?"
        args.append(start)
    if end:
        sql += " AND at <= ?"
        args.append(end + "T23:59:59")
    if action:
        sql += " AND action = ?"
        args.append(action)
    if not logins:
        sql += " AND action NOT IN ('로그인','로그아웃','로그인 실패')"
    rows = db.q(sql + " ORDER BY id DESC LIMIT 5000", args)
    actions = [r["action"] for r in db.q("SELECT DISTINCT action FROM audit_logs ORDER BY action")]
    return rows, actions


@app.get("/admin/audit-logs.csv")
def admin_audit_csv(request: Request, start: str = "", end: str = "", action: str = "", logins: int = 0):
    rows, _ = _audit_rows(start, end, action, logins)
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["시간", "사용자", "작업", "대상", "IP"])
    for r in rows:
        w.writerow([r["at"].replace("T", " "), r["user"], r["action"], r["target"], r["ip"]])
    return Response("﻿" + out.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=audit_logs.csv"})


@app.get("/admin/policies", response_class=HTMLResponse)
def admin_policies(request: Request):
    rows = db.q("SELECT * FROM policies ORDER BY key")
    cnt = {k: sum(1 for r in rows if r["category"] == k) for k in ("규정", "표준", "정책")}
    return render(request, "admin_policies.html", {"rows": rows, "cnt": cnt})


@app.post("/admin/policies")
async def admin_policy_save(request: Request):
    u = cur_user(request)
    if not is_admin(u):
        return deny(request, "/admin/policies")
    f = await request.form()
    key, val = f.get("key"), (f.get("value") or "").strip()
    old = db.one("SELECT value FROM policies WHERE key=?", (key,))
    policy.set_value(key, val, u["username"])
    db.audit(u["username"], "정책값 변경", f"{key}: {old['value'] if old else ''} → {val}", ip(request))
    flash(request, "ok", f"{key} 값을 저장했습니다. 이후 계산부터 반영됩니다.")
    return back("/admin/policies")


@app.get("/admin/system", response_class=HTMLResponse)
def admin_system(request: Request):
    from core import llm, rag
    eng, path = scanner.find_engine()
    return render(request, "admin_system.html", {
        "engine": scanner.engine_version() if eng else "미설치", "engine_path": path, "rules": scanner.rule_files(),
        "ruleset_sha": scanner.ruleset_sha256() if scanner.rule_files() else "", "ai_label": llm.provider_label(),
        "ai_ok": llm.available(), "index": rag.index_info(), "docs": rag.DOCS, "pdf_ok": bool(pdfmod.find_browser()),
        "db_path": config.DB_PATH, "counts": {t: db.one(f"SELECT COUNT(*) AS n FROM {t}")["n"]
                                              for t in ("devices", "scans", "findings", "assessments", "reports", "audit_logs")}})


@app.post("/admin/system/reindex")
def admin_reindex(request: Request):
    u = cur_user(request)
    if not is_admin(u):
        return deny(request, "/admin/system")
    from core import rag
    rag.build_index()
    rag.reset_cache()
    db.audit(u["username"], "검색 색인 재생성", "", ip(request))
    flash(request, "ok", "규제 문서 검색 색인을 다시 만들었습니다.")
    return back("/admin/system")
