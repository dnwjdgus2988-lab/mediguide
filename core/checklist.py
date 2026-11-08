"""보안 체크리스트(SPDF 4개 영역 20문항, 100점)·증빙 13종·문서 충족률·등급·FDA 제출 적합성.

산식은 화면·리포트에 그대로 공개한다. 배점·적용조건·등급 구간은 관리자 ▸ 정책값에서 바꿀 수 있다.
"""
from core import policy

AREAS = {
    1: "보안 위협 관리",
    2: "보안 아키텍처",
    3: "사이버보안 테스트",
    4: "사이버보안 투명성",
}

# id, 영역, 문항, 배점, 연계 증빙, 근거, 증빙 없으면 50% 인정, 적용조건, 법정
QUESTIONS = [
    ("Q1", 1, "위험 모델링(Threat Modeling)을 수행했는가?", 8, ["D01"], "V.A.1", True, "ALWAYS", False),
    ("Q2", 1, "공격 시나리오 및 신뢰 경계(Trust Boundary)를 정의했는가?", 4, ["D01"], "V.A.1", True, "ALWAYS", False),
    ("Q3", 1, "서드파티 소프트웨어 위험 평가를 수행했는가?", 4, ["D02"], "V.A.4", False, "SOFTWARE", False),
    ("Q4", 1, "악용가능성 기반 사이버보안 위험평가를 수행했는가? (안전성 위험분석과 별도)", 7, ["D02"], "V.A.2", True, "ALWAYS", False),
    ("Q5", 1, "미해결 이상(Unresolved Anomalies)의 보안 영향을 평가했는가?", 4, ["D03"], "V.A.5", True, "ALWAYS", False),
    ("Q6", 2, "보안 요구사항을 도출하고 문서화했는가?", 6, ["D04"], "V.B.1", False, "ALWAYS", False),
    ("Q7", 2, "인증·암호화·업데이트 메커니즘의 보안 아키텍처 문서가 있는가?", 4, ["D05"], "V.B", True, "ALWAYS", False),
    ("Q8", 2, "전역 시스템 뷰(요소↔보안요구 추적 포함)를 작성했는가?", 4, ["D05"], "V.B.2", True, "ALWAYS", False),
    ("Q9", 2, "다중 환자 위해(Multi-Patient Harm) 뷰를 작성했는가?", 3, ["D05"], "V.B.2", False, "INTERNET", False),
    ("Q10", 2, "패치 가능성(Updatability/Patchability) 뷰를 작성했는가?", 3, ["D05"], "V.B.2", True, "SOFTWARE", False),
    ("Q11", 2, "보안 유스케이스 뷰를 작성했는가?", 3, ["D05"], "V.B.2", True, "ALWAYS", False),
    ("Q12", 3, "정적분석(SAST) 및 취약점 스캔을 수행했는가?", 6, ["D06"], "V.C", False, "SOFTWARE", False),
    ("Q13", 3, "침투테스트 결과 보고서가 있는가? (full-scope · 방법론 명시)", 6, ["D07"], "V.C", True, "ALWAYS", False),
    ("Q14", 3, "보안 요구사항별 구현 검증 증거가 있는가?", 5, ["D06", "D07"], "V.C", True, "ALWAYS", False),
    ("Q15", 3, "위험통제(완화조치) 유효성 테스트 증거가 있는가?", 4, ["D07"], "V.C", False, "ALWAYS", False),
    ("Q16", 4, "SBOM을 작성·보유하고 있는가? (기계판독 SPDX 또는 CycloneDX)", 8, ["D08"], "§524B(b)(3) · VII.C.3 · VI.A", True, "SECTION_524B", True),
    ("Q17", 4, "취약점 모니터링 및 대응 계획이 수립되었는가?", 6, ["D09"], "§524B(b)(1) · VII.C.1 · VI.B", True, "SECTION_524B", True),
    ("Q18", 4, "사이버보안 관리계획 문서를 수립·보유하고 있는가?", 6, ["D13"], "§524B(b)(2) · VII.C.2", False, "SECTION_524B", True),
    ("Q19", 4, "협력적 취약점 공개(CVD) 절차를 보유하는가?", 4, ["D10"], "§524B(b)(1) · VII.C.1", True, "SECTION_524B", False),
    ("Q20", 4, "사용자 대상 보안 라벨링(보안 안내 문서)을 갖추었는가?", 5, ["D11"], "VI.A", True, "ALWAYS", False),
]
Q = {q[0]: dict(id=q[0], area=q[1], text=q[2], points=q[3], evidence=q[4], basis=q[5],
                half=q[6], cond=q[7], legal=q[8]) for q in QUESTIONS}

COND_TEXT = {
    "ALWAYS": "모든 기기",
    "SOFTWARE": "소프트웨어를 포함한 기기",
    "INTERNET": "인터넷에 연결할 수 있는 기기",
    "SECTION_524B": "§524B 적용 대상 사이버 기기",
}

# 증빙 13종: 코드, 이름, 구분(법정/필수/권고/선택), 연계 문항
EVIDENCE = [
    ("D01", "위협모델링 보고서 (STRIDE 등 방법론 명시)", "필수", ["Q1", "Q2"]),
    ("D02", "사이버보안 위험평가서 (악용가능성 기반)", "필수", ["Q3", "Q4"]),
    ("D03", "미해결 이상 평가서", "권고", ["Q5"]),
    ("D04", "보안 요구사항 명세서", "필수", ["Q6"]),
    ("D05", "보안 아키텍처 문서 (4개 뷰)", "필수", ["Q7", "Q8", "Q9", "Q10", "Q11"]),
    ("D06", "SAST · 취약점 스캔 결과보고서", "필수", ["Q12", "Q14"]),
    ("D07", "침투테스트 보고서 (full-scope)", "필수", ["Q13", "Q14", "Q15"]),
    ("D08", "SBOM (SPDX 또는 CycloneDX)", "법정", ["Q16"]),
    ("D09", "사이버보안 관리계획 (CMP)", "법정", ["Q17"]),
    ("D10", "CVD (협력적 취약점 공개) 절차서", "필수", ["Q19"]),
    ("D11", "보안 라벨링 (사용자 보안 안내)", "권고", ["Q20"]),
    ("D12", "기타 증빙 (자유)", "선택", []),
    ("D13", "보안 업데이트 · 패치 절차서", "법정", ["Q18"]),
]
EV = {e[0]: dict(code=e[0], name=e[1], level=e[2], qs=e[3]) for e in EVIDENCE}

LEGAL_LABEL = {  # 법정 문항 → 미충족 시 표시 문구
    "Q16": ("SBOM", "§524B(b)(3)"),
    "Q17": ("취약점 모니터링·대응 계획", "§524B(b)(1)"),
    "Q18": ("보안 업데이트·패치 절차", "§524B(b)(2)"),
}
FDA_PATHS = ["510(k)", "De Novo", "PMA", "PDP", "HDE"]


# ── 사이버 기기 · 적용조건 ─────────────────────────────────
def cyber_status(device):
    """§524B(c) 세 조건이 모두 '예'면 사이버 기기."""
    vals = [device.get("has_software"), device.get("internet"), device.get("vuln_tech")]
    if any(v is None for v in vals):
        return "미판정"
    return "사이버 기기 해당" if all(vals) else "사이버 기기 비해당"


def fda_paths():
    return [p.strip() for p in policy.get("submission.fda_paths", ",".join(FDA_PATHS)).split(",") if p.strip()]


def section_524b(device):
    return (device.get("target_market") == "미국 FDA" and device.get("submission_path") in fda_paths()
            and cyber_status(device) == "사이버 기기 해당")


def applicable(qid, device):
    cond = policy.get(f"checklist.applicability.{qid}", Q[qid]["cond"])
    if cond == "ALWAYS":
        return True
    if cond == "SOFTWARE":
        return device.get("has_software") != 0
    if cond == "INTERNET":
        return device.get("internet") != 0
    if cond == "SECTION_524B":
        return section_524b(device)
    return True


def points(qid):
    try:
        return float(policy.get(f"checklist.points.{qid}", Q[qid]["points"]))
    except ValueError:
        return float(Q[qid]["points"])


# ── 채점 ───────────────────────────────────────────────────
def score(answers: dict, device: dict, evidence_slots: set):
    """answers: {Q1: '예'|'아니오'|'비적용'|None}. evidence_slots: 업로드된 증빙 코드 집합.

    「예」는 연계 증빙이 있으면 배점 전부, 없으면 50%만 인정(문항별 규칙).
    「비적용」과 적용조건에 해당하지 않는 문항은 분모에서 뺀다."""
    half_ratio = float(policy.get("checklist.half_credit_ratio", "0.5"))
    rows, areas = [], {a: {"got": 0.0, "max": 0.0, "answered": 0, "total": 0} for a in AREAS}
    counts = {"충족": 0, "증빙 미비": 0, "미충족": 0, "미응답": 0, "비적용": 0}
    got_total = max_total = 0.0
    for qid, qq in Q.items():
        ans = answers.get(qid)
        appl = applicable(qid, device)
        pts = points(qid)
        has_ev = any(e in evidence_slots for e in qq["evidence"])
        a = areas[qq["area"]]
        a["total"] += 1
        state, got = "미응답", 0.0
        if not appl or ans == "비적용":
            state = "비적용"
            a["answered"] += 1
        elif ans == "예":
            a["answered"] += 1
            if has_ev or not qq["half"]:
                state, got = "충족", pts
            else:
                state, got = "증빙 미비", pts * half_ratio
        elif ans == "아니오":
            a["answered"] += 1
            state = "미충족"
        counts[state] += 1
        if state != "비적용":
            a["max"] += pts
            max_total += pts
            a["got"] += got
            got_total += got
        rows.append(dict(qq, answer=ans, applicable=appl, pts=pts, got=got, state=state, has_evidence=has_ev,
                         cond_text=COND_TEXT.get(qq["cond"], qq["cond"])))
    rate = round(got_total / max_total * 100, 1) if max_total else 0.0
    answered = sum(1 for r in rows if r["state"] != "미응답")
    return {
        "rows": rows, "areas": areas, "counts": counts, "rate": rate,
        "got": round(got_total, 1), "max": round(max_total, 1),
        "progress": round(answered / len(rows) * 100),
        "legal_gaps": legal_gaps(rows),
    }


def legal_gaps(rows):
    """법정 제출요건: 적용 대상인데 「예 + 연계 증빙」이 아닌 법정 문항."""
    out = []
    for r in rows:
        if r["legal"] and r["applicable"] and r["state"] != "비적용" and not (r["answer"] == "예" and r["has_evidence"]):
            name, ref = LEGAL_LABEL[r["id"]]
            out.append({"qid": r["id"], "name": name, "ref": ref})
    return out


# ── 등급 ───────────────────────────────────────────────────
def base_grade(rate):
    a = float(policy.get("grade.band.A", "90"))
    b = float(policy.get("grade.band.B", "80"))
    c = float(policy.get("grade.band.C", "70"))
    return "A" if rate >= a else "B" if rate >= b else "C" if rate >= c else "D"


ORDER = "ABCD"


def final_grade(rate, sev_counts: dict):
    """문서 충족률로 기본 등급을 내고, 미해결 취약점이 있으면 등급 상한을 건다."""
    base = base_grade(rate)
    cap, reason = None, ""
    crit, high = sev_counts.get("Critical", 0), sev_counts.get("High", 0)
    cap_hi = policy.get("grade.cap.critical_high", "D")
    cap_med = policy.get("grade.cap.medium", "")
    if crit or high:
        cap = cap_hi
        parts = []
        if crit:
            parts.append(f"Critical 취약점 {crit}건")
        if high:
            parts.append(f"High 취약점 {high}건")
        reason = " · ".join(parts) + " (인허가 신청 전 필수 해결)"
    elif cap_med and sev_counts.get("Medium", 0):
        cap = cap_med
        reason = f"Medium 취약점 {sev_counts['Medium']}건 (차기 배포 버전 내 해결 권고)"
    final = base
    if cap and ORDER.index(cap) > ORDER.index(base):
        final = cap
    return {"base": base, "cap": cap, "cap_reason": reason, "final": final}


def fda_verdict(device, result, grade):
    """기기 목록의 FDA 적합성. result=None 이면 승인된 평가가 없다는 뜻."""
    if device.get("target_market") != "미국 FDA" or cyber_status(device) == "사이버 기기 비해당":
        return "해당 없음"
    if result is None:
        return "판정 불가"
    if result["legal_gaps"]:
        return "부적합"
    if grade and grade["final"] in ("A", "B"):
        return "적합"
    return "조건부 적합"


GRADE_TEXT = {
    "A": "양호 — 제출 준비 수준",
    "B": "보통 — 일부 보완 후 제출 권장",
    "C": "미흡 — 주요 항목 보완 필요",
    "D": "위험 — 제출 전 반드시 보완·조치 필요",
}
