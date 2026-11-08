"""표준화 검증: 요구항목 DB(12개) 자동 판정 → 4축 지표 → 관할별(FDA·MFDS·MDR·IMDRF) 판정.

기존 데이터(기기 정보·체크리스트·증빙·스캔)로 자동 판정하고, 검토자가 상태를 지정하면 그 값을 유지한다.
"""
from core import db

STATUSES = ["충족", "보완 필요", "검토 필요", "해당 없음"]

# id, 구분, 요구항목, 분류, 출처 기관, 조항, 적용성, 적용조건, 정규화 요구내용, 요구 증빙, 연계 문항, 연계 증빙, 의무
REQS = [
    ("FDA-APP-01", "법적 요구", "적용 대상 제출 경로 확인", "적용성", "US Congress / FDA", "§524B(a), FDA FAQ Q1", "적용성 평가",
     "시장=미국 FDA AND 제출경로가 지정 목록에 포함", "510(k), PMA, PDP, De Novo 또는 HDE 제출인지 확인한다.",
     ["시장·제출전략서", "제출경로 결정 기록"], [], [], "법정"),
    ("FDA-CYBER-01", "법적 요구", "Cyber device 해당성 확인", "적용성", "US Congress / FDA", "§524B(c)", "필수 확인",
     "세 조건 모두 Yes이면 cyber device", "소프트웨어 포함, 인터넷 연결 가능, 사이버 위협에 취약한 기술적 특성 세 가지를 확인한다.",
     ["사이버 기기 판정 기록"], [], [], "법정"),
    ("FDA-524B-B1", "법적 요구", "시판 후 취약점 관리 계획", "시판 후 관리", "US Congress / FDA", "§524B(b)(1)", "적용",
     "§524B 적용 대상 cyber device", "시판 후 사이버보안 취약점·익스플로잇을 모니터링하고 식별·대응하는 계획을 제출한다(협력적 취약점 공개 포함).",
     ["취약점 모니터링 계획", "CVD 절차서", "대응 일정"], ["Q17", "Q19"], ["D09"], "법정"),
    ("FDA-524B-B2", "법적 요구", "합리적 사이버보안 및 업데이트 절차", "보안 유지보수", "US Congress / FDA", "§524B(b)(2)", "적용",
     "§524B 적용 대상 cyber device", "기기와 관련 시스템의 사이버보안을 합리적으로 보증하는 절차를 설계·개발·유지하고, 시판 후 업데이트·패치를 제공한다.",
     ["보안 업데이트 정책", "패치 절차서", "사이버보안 관리계획"], ["Q18"], ["D13"], "법정"),
    ("FDA-524B-B3", "법적 요구", "SBOM 제공", "구성요소 관리", "US Congress / FDA", "§524B(b)(3)", "적용",
     "§524B 적용 대상 cyber device", "상용·오픈소스·기성 소프트웨어 구성요소를 포함한 소프트웨어 자재명세서(SBOM)를 제공한다.",
     ["SBOM", "구성요소 지원 수준·종료일", "알려진 취약점 평가"], ["Q16"], ["D08"], "법정"),
    ("FDA-GD-TM", "FDA 권고", "위협 모델링 및 보안 위험 분석", "위험 분석", "FDA", "Guidance Section V", "적용",
     "미국 제출 + 사이버보안 위험이 있는 기기", "위협 모델링으로 공격면·신뢰 경계를 식별하고 악용가능성 기반 보안 위험평가를 수행한다.",
     ["위협 모델", "보안 위험평가서", "위험 통제 추적표"], ["Q1", "Q2", "Q4"], ["D01", "D02"], "권고"),
    ("FDA-GD-ARCH", "FDA 권고", "보안 아키텍처 문서화", "설계", "FDA", "Guidance Section V", "적용",
     "미국 제출 + 사이버보안 위험이 있는 기기", "전역 시스템·다중 환자 위해·업데이트 가능성·보안 유스케이스 뷰로 보안 아키텍처를 문서화한다.",
     ["시스템 아키텍처", "아키텍처 뷰 4종", "보안 요구 추적"], ["Q7", "Q8", "Q9", "Q10", "Q11"], ["D05"], "권고"),
    ("FDA-GD-TEST", "FDA 권고", "사이버보안 시험 및 결과 추적", "검증", "FDA", "Guidance Section V", "적용",
     "미국 제출 + 사이버보안 위험이 있는 기기", "보안 요구사항 구현 검증, 정적·동적 분석, 침투시험을 수행하고 결과를 요구사항과 추적한다.",
     ["보안 시험계획", "SAST 결과보고서", "침투시험 보고서"], ["Q12", "Q13", "Q14", "Q15"], ["D06", "D07"], "권고"),
    ("MAP-81001-SDLC", "표준 매핑", "보안 개발수명주기 활동 매핑", "표준 매핑", "IEC", "세부 조항 매핑 대기", "참조·적용",
     "조직이 IEC 81001-5-1을 적용 또는 참조하는 경우", "보안 개발수명주기 활동을 IEC 81001-5-1 조항과 대응시킨다.",
     ["정식 표준 보유본", "조항 대응표", "프로세스 기록"], [], [], "권고"),
    ("MAP-62304-SLC", "표준 매핑", "소프트웨어 생명주기 프로세스 매핑", "표준 매핑", "IEC", "세부 조항 매핑 대기", "참조·적용",
     "의료기기 소프트웨어 또는 내장 소프트웨어 개발", "소프트웨어 생명주기 산출물을 IEC 62304 조항과 대응시킨다.",
     ["정식 표준 보유본", "조항 대응표", "SW 개발 계획"], [], [], "권고"),
    ("MAP-14971-RM", "표준 매핑", "의료기기 위험관리 프로세스 매핑", "표준 매핑", "ISO", "세부 조항 매핑 대기", "참조·적용",
     "의료기기 위험관리 체계 적용", "보안 위험관리 결과를 ISO 14971 위험관리 파일과 연결한다.",
     ["정식 표준 보유본", "위험관리 파일", "대응표"], [], [], "권고"),
    ("MH-COVERAGE-01", "내부 기준", "분석 범위와 미검사 영역 표시", "보고 품질", "메디가이드", "Internal policy draft 0.1", "참조·적용",
     "메디가이드 분석 보고서 발행 시", "정적분석 리포트에 분석 대상·제외 경로·미검사 범위를 표시한다.",
     ["분석 범위 기록"], [], [], "내부"),
]
R = {r[0]: dict(id=r[0], kind=r[1], title=r[2], category=r[3], org=r[4], clause=r[5], appl=r[6], cond=r[7],
                text=r[8], evidence_req=r[9], qs=r[10], slots=r[11], duty=r[12]) for r in REQS}

JURIS = ["미국 FDA", "한국 MFDS", "유럽 CE · MDR", "국제 IMDRF"]
_ALL_BUT_INTERNAL = [k for k in R if not k.startswith("MH-")]
JURIS_ITEMS = {
    "미국 FDA": _ALL_BUT_INTERNAL,
    "한국 MFDS": _ALL_BUT_INTERNAL,
    "유럽 CE · MDR": _ALL_BUT_INTERNAL,
    "국제 IMDRF": [k for k in _ALL_BUT_INTERNAL if not k.startswith("FDA-524B")],
}
AXIS_ITEMS = {
    "completeness": ["FDA-APP-01", "FDA-CYBER-01", "FDA-524B-B1", "FDA-524B-B2", "FDA-524B-B3"],
    "traceability": ["FDA-GD-TM", "FDA-GD-ARCH", "FDA-GD-TEST", "MH-COVERAGE-01"],
}


def _auto(req, device, answers, slots, has_scan):
    from core import checklist
    rid = req["id"]
    if rid == "FDA-APP-01":
        return "충족" if device.get("target_market") == "미국 FDA" and device.get("submission_path") in checklist.fda_paths() else "보완 필요"
    if rid == "FDA-CYBER-01":
        return "충족" if checklist.cyber_status(device) != "미판정" else "보완 필요"
    if rid.startswith("FDA-524B"):
        if not checklist.section_524b(device):
            return "해당 없음"
        ok = all(answers.get(q) == "예" for q in req["qs"][:1]) and all(s in slots for s in req["slots"])
        return "충족" if ok else "보완 필요"
    if rid.startswith("FDA-GD"):
        qs = [q for q in req["qs"] if checklist.applicable(q, device)]
        if qs and all(answers.get(q) in ("예", "비적용") for q in qs) and all(s in slots for s in req["slots"]):
            return "충족"
        return "검토 필요"
    if rid == "MH-COVERAGE-01":
        return "충족" if has_scan else "검토 필요"
    return "검토 필요"


def evaluate(device, answers, slots, has_scan, uploaded_files=None):
    """반환: rows(항목별), counts, axes(4축), verdicts(관할별)."""
    overrides = {r["req_id"]: r for r in db.q("SELECT * FROM std_status WHERE device_id=?", (device["id"],))}
    rows = []
    for rid, req in R.items():
        auto = _auto(req, device, answers, slots, has_scan)
        ov = overrides.get(rid)
        status = ov["status"] if ov and ov.get("status") else auto
        rows.append(dict(req, auto=auto, status=status, manual=bool(ov and ov.get("status")),
                         memo=(ov or {}).get("memo") or "", by=(ov or {}).get("user"), at=(ov or {}).get("at")))
    by = {r["id"]: r for r in rows}
    counts = {
        "total": len(rows),
        "met": sum(r["status"] == "충족" for r in rows),
        "gap": sum(r["status"] == "보완 필요" for r in rows),
        "review": sum(r["status"] == "검토 필요" for r in rows),
    }
    reviewed = sum(1 for r in rows if r["manual"] or r["status"] in ("충족", "보완 필요", "해당 없음"))
    counts["review_done_pct"] = round(reviewed / len(rows) * 100)

    def ratio(items):
        items = [i for i in items if by[i]["status"] != "해당 없음"]
        if not items:
            return None, 0, 0
        n = sum(by[i]["status"] == "충족" for i in items)
        return round(n / len(items) * 100, 1), n, len(items)

    comp = ratio(AXIS_ITEMS["completeness"])
    # 증빙 충분성: 연계 문항에 「예」라고 답한 법적·권고 항목 중 연계 증빙이 실제로 올라온 비율
    claimed = [r for r in rows if r["slots"] and r["qs"] and answers.get(r["qs"][0]) == "예" and r["status"] != "해당 없음"]
    ev_n = sum(all(s in slots for s in r["slots"]) for r in claimed)
    evid = (round(ev_n / len(claimed) * 100, 1) if claimed else None, ev_n, len(claimed))
    # 추적성: 권고·내부 항목 중 충족이면서 증빙(또는 스캔 기록)과 연결된 비율
    tr_items = [i for i in AXIS_ITEMS["traceability"] if by[i]["status"] != "해당 없음"]
    tr_n = sum(1 for i in tr_items if by[i]["status"] == "충족" and by[i]["slots"] and all(s in slots for s in by[i]["slots"]))
    trace = (round(tr_n / len(tr_items) * 100, 1) if tr_items else None, tr_n, len(tr_items))
    # 형식 준수성: 증빙이 올라온 요구항목 중 형식검사 F1~F3 통과 비율
    files = uploaded_files or []
    fmt_items = [r for r in rows if r["slots"] and any(s in slots for s in r["slots"])]
    fmt_n = sum(1 for r in fmt_items if all(_format_ok(f) for f in files if f["slot"] in r["slots"]))
    fmt = (round(fmt_n / len(fmt_items) * 100, 1) if fmt_items else None, fmt_n, len(fmt_items))
    axes = [("항목 완전성", comp), ("증빙 충분성", evid), ("추적성", trace), ("형식 준수성", fmt)]

    verdicts = []
    for j in JURIS:
        items = [by[i] for i in JURIS_ITEMS[j] if by[i]["status"] != "해당 없음"]
        unmet = [r for r in items if r["status"] != "충족"]
        legal_unmet = [r for r in unmet if r["duty"] == "법정"]
        if legal_unmet:
            v = "부적합"
        elif unmet:
            v = "조건부 적합"
        else:
            v = "적합"
        verdicts.append({"juris": j, "verdict": v, "n": len(items), "unmet": len(unmet), "legal_unmet": len(legal_unmet)})
    return {"rows": rows, "counts": counts, "axes": axes, "verdicts": verdicts}


def _format_ok(f):
    """F1 허용 형식, F2 빈 파일 아님, F3 파일 이름에 깨진 문자 없음."""
    from core import policy
    allowed = {e.strip().lower() for e in policy.get("evidence.allowed_ext", "pdf").split(",")}
    ext = (f.get("filename") or "").rsplit(".", 1)[-1].lower()
    return ext in allowed and (f.get("size") or 0) > 0 and "�" not in (f.get("filename") or "")


def set_status(device_id, req_id, status, memo, user):
    db.run("""INSERT INTO std_status(device_id, req_id, status, memo, user, at) VALUES(?,?,?,?,?,?)
              ON CONFLICT(device_id, req_id) DO UPDATE SET status=excluded.status, memo=excluded.memo,
              user=excluded.user, at=excluded.at""", (device_id, req_id, status or None, memo, user, db.now()))
