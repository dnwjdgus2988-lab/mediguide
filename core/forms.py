"""관할별 결과보고서 (식약처 시험성적서 · FDA Test Report · EU Test Report) — 정적분석 시험 결과 양식.

뼈대: ISO/IEC 17025:2017 7.8(시험보고서 기재사항)
  식약처 — 시험성적서 첫 장 + 시험 결과 상세 + 안내서-0995-05 [표3] 요구사항 연결
  FDA    — Recommended Content and Format of Non-Clinical Bench Performance Testing (2019) 요약·전체 보고서 순서
  EU     — 같은 시험보고서 뼈대 + MDR Annex I GSPR 17.2/17.4, IEC 81001-5-1 연결
자동으로 채울 수 있는 칸(기기·시료·도구·해시·검출·처분)은 채우고, 사람이 적어야 하는 칸은 빈칸 안내로 둔다.
"""
from datetime import datetime

from core import db, scanner, service

KINDS = {
    "mfds": {"title": "식약처 시험성적서", "sub": "의료기기 사이버보안 — 소스코드 정적분석", "file": "식약처_시험성적서_정적분석",
             "tpl": "forms/mfds.html", "desc": "국내 허가·심사 제출용. 안내서-0995-05 [표3] 요구사항 체크리스트와 검출을 연결합니다.", "lang": "ko"},
    "fda": {"title": "FDA Test Report", "sub": "Static Code Analysis of Device Software", "file": "FDA_Test_Report_SAST",
            "tpl": "forms/fda.html", "desc": "eSTAR 사이버보안 섹션 「Cybersecurity Testing」 첨부용. FDA 2019 시험보고서 권고 순서.", "lang": "en"},
    "eu": {"title": "EU Test Report", "sub": "Static Code Analysis (MDR Technical Documentation)", "file": "EU_Test_Report_SAST",
           "tpl": "forms/fda.html", "desc": "MDR 기술문서 V&V 첨부용. GSPR 17.2·17.4, IEC 81001-5-1 연결 포함.", "lang": "en"},
    "ua": {"title": "FDA 미해결 이상 평가서", "sub": "Assessment of Unresolved Anomalies", "file": "FDA_Unresolved_Anomalies",
           "tpl": "forms/ua.html", "desc": "eSTAR 530칸 첨부용. 남기는 약점과 출시 전 고쳐야 할 결함을 나눠 적습니다.", "lang": "en"},
    "estar": {"title": "eSTAR 사이버보안 기입표", "sub": "eSTAR v7.1 Cybersecurity 섹션", "file": "eSTAR_사이버보안섹션_기입표",
              "tpl": "forms/estar.html", "desc": "eSTAR 칸 번호별로 무엇을 붙이고 적을지, 메디가이드 산출물과 증빙이 어느 칸에 가는지 정리합니다.", "lang": "ko"},
}

# CWE → 식약처 안내서-0995-05 [표3] 요구사항
CWE_KR = {
    "CWE-787": ["SI-05"], "CWE-120": ["SI-05"], "CWE-20": ["SI-05"], "CWE-134": ["SI-05", "SI-07"],
    "CWE-798": ["IA-04"], "CWE-327": ["DC-03"], "CWE-338": ["DC-03"], "CWE-306": ["IA-01", "UC-01"],
}
KR_NAME = {"SI-05": "입력값 검증", "SI-07": "오류 처리", "IA-04": "인증정보 관리", "DC-03": "안전한 암호화 사용",
           "IA-01": "사용자 식별 및 인증", "UC-01": "권한 부여"}
KR_REQ = [("식별 및 인증", "IA", [("IA-01", "사용자 식별 및 인증"), ("IA-02", "계정 관리"), ("IA-03", "식별정보 관리"), ("IA-04", "인증정보 관리"),
                                 ("IA-05", "비밀번호 강도 설정"), ("IA-06", "인증정보에 대한 피드백"), ("IA-07", "연속적인 로그인 시도 실패 시 로그인 제한"),
                                 ("IA-08", "시스템 사용 알림 메시지")]),
          ("사용 통제", "UC", [("UC-01", "권한 부여"), ("UC-02", "모바일 코드 사용 통제"), ("UC-03", "세션 잠금"), ("UC-04", "감사기록 생성"),
                              ("UC-05", "감사 처리 실패 대응"), ("UC-06", "타임스탬프"), ("UC-07", "부인 방지")]),
          ("시스템 무결성", "SI", [("SI-01", "통신에 대한 무결성 보장"), ("SI-02", "악성코드로부터 보호"), ("SI-03", "보안 기능 검증"),
                                ("SI-04", "소프트웨어 및 정보에 대한 무결성 점검"), ("SI-05", "입력값 검증"), ("SI-06", "오류 시 사전 결정된 상태로 출력"),
                                ("SI-07", "오류 처리"), ("SI-08", "업데이트"), ("SI-09", "업데이트에 대한 진본성 및 무결성 검증"), ("SI-10", "물리적 변조 방지"),
                                ("SI-11", "부트 프로세스 무결성 검증")]),
          ("데이터 기밀성", "DC", [("DC-01", "정보에 대한 기밀성 보장"), ("DC-02", "보건의료정보 비식별화"), ("DC-03", "안전한 암호화 사용")]),
          ("이벤트 적시 대응", "TRE", [("TRE-01", "감사로그에 대한 비인가된 접근 제한")]),
          ("자원 가용성", "RA", [("RA-01", "서비스 거부(Denial of Service, DoS) 방지"), ("RA-02", "의료기기 백업"), ("RA-03", "의료기기 복구 및 재구성"),
                               ("RA-04", "네트워크 및 보안 구성 설정"), ("RA-05", "불필요한 기능 비활성화")])]
# CWE → FDA 2026 가이던스 Appendix 1 보안 통제 범주
CWE_CTRL = {"CWE-787": "D", "CWE-120": "D", "CWE-20": "D", "CWE-134": "D", "CWE-798": "A", "CWE-306": "A",
            "CWE-327": "C", "CWE-338": "C"}
CTRL = {"A": "Authentication", "B": "Authorization", "C": "Cryptography", "D": "Code, Data, and Execution Integrity",
        "E": "Confidentiality", "F": "Event Detection and Logging", "G": "Resiliency and Recovery", "H": "Updatability and Patchability"}
DISP_EN = {"확인된 결함": "Confirmed defect", "약점": "Weakness", "오탐": "False positive", "연기": "Deferred", "검토 필요": "Not yet reviewed"}
SEV_KO = {"Critical": "치명", "High": "높음", "Medium": "보통", "Low": "낮음", "None": "없음"}
ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4}


def _ac(fs, scan):
    """판정 기준 AC-1~4 측정."""
    n = len(fs)
    reviewed = [f for f in fs if f["disposition"] and f["disposition"] != "검토 필요" and (f["rationale"] or "").strip()]
    high_open = [f for f in fs if f["disposition"] == "확인된 결함"
                 and ORDER.get(f["assessed_severity"] or f["severity"], 9) <= ORDER["High"]]
    files = scan["files_scanned"] if scan else 0
    ac = [
        {"id": "AC-1", "ko": "분석 범위 안 소스 파일 분석 비율", "en": "Share of in-scope source files analysed", "req": "100%",
         "val": f"{files}/{files} (100%), 미분석 0" if scan else "—", "val_en": f"{files}/{files} (100%), 0 unscanned" if scan else "—",
         "ok": bool(scan)},
        {"id": "AC-2", "ko": "처분·근거를 적은 검출 비율", "en": "Share of findings with disposition and rationale", "req": "100%",
         "val": f"{len(reviewed)}/{n} ({(len(reviewed) / n * 100 if n else 100):.0f}%)",
         "val_en": f"{len(reviewed)}/{n} ({(len(reviewed) / n * 100 if n else 100):.0f}%)", "ok": len(reviewed) == n},
        {"id": "AC-3", "ko": "평가 심각도 「높음」 이상 미해결 확인된 결함 수", "en": "Open confirmed defects of assessed severity High or above",
         "req": "0건", "val": f"{len(high_open)}건", "val_en": str(len(high_open)), "ok": not high_open},
        {"id": "AC-4", "ko": "도구·버전·설정·검사 기준 SHA-256 기록", "en": "Tool, version, configuration and rule-set SHA-256 recorded",
         "req": "전부 기록", "val": "전부 기록" if scan and scan.get("ruleset_sha256") else "일부 누락",
         "val_en": "All recorded" if scan and scan.get("ruleset_sha256") else "Incomplete",
         "ok": bool(scan and scan.get("ruleset_sha256"))},
    ]
    if not ac[1]["ok"]:
        overall = ("hold", "판정 보류", "Pending")
    elif all(a["ok"] for a in ac):
        overall = ("pass", "기준 충족", "Pass")
    else:
        overall = ("fail", "기준 미충족", "Fail")
    return ac, overall, high_open


def context(r, kind):
    snap = r["snap"]
    dev, scan = snap["device"], snap.get("scan")
    fs = service.findings(scan["id"]) if scan else []
    for i, f in enumerate(fs, 1):
        f["fid"] = f"F-{i:02d}"
        f["kr_req"] = CWE_KR.get(f["cwe"], [])
        f["ctrl"] = CWE_CTRL.get(f["cwe"], "")
        f["disp_en"] = DISP_EN.get(f["disposition"] or "검토 필요", f["disposition"])
        meta = scanner.rule_detail(f["rule_id"])
        f["name_en"] = meta.get("name_en", f["rule_id"])
        f["desc_ko"] = meta.get("description_ko", "")
        f["fix_ko"] = meta.get("remediation_ko", [])
    ac, overall, high_open = _ac(fs, scan)
    by_disp = {}
    for f in fs:
        by_disp.setdefault(f["disposition"] or "검토 필요", []).append(f)
    req_find = {}
    for f in fs:
        for k in f["kr_req"]:
            req_find.setdefault(k, []).append(f["fid"])
    ctrl_find = {}
    for f in fs:
        if f["ctrl"]:
            ctrl_find.setdefault(f["ctrl"], []).append(f["fid"])
    rules = []
    msgs = scanner.load_rule_messages()
    for rid, m in msgs.items():
        rules.append({"id": rid, "cwe": m.get("cwe"), "ko": m.get("name_ko"), "en": m.get("name_en"), "sev": m.get("severity"),
                      "cvss": m.get("cvss")})
    doc_no = f"MG-{dev['code'].replace('-', '')}-{kind.upper()}-TR-{r['id']:02d}"
    ev = {e["code"]: e for e in snap.get("evidence", [])}
    sb = snap.get("sbom") or {}
    return {"ev": ev, "sb": sb, "sbv": snap.get("sbom_vuln", []), "r": r, "s": snap, "dev": dev, "scan": scan, "fs": fs, "ac": ac, "overall": overall, "high_open": high_open,
            "by_disp": by_disp, "req_find": req_find, "ctrl_find": ctrl_find, "rules": rules, "doc_no": doc_no,
            "KR_REQ": KR_REQ, "KR_NAME": KR_NAME, "CTRL": CTRL, "SEV_KO": SEV_KO, "kind": KINDS[kind], "kind_key": kind,
            "today": datetime.now().strftime("%Y. %m. %d."), "today_en": datetime.now().strftime("%Y-%m-%d"),
            "langs": (scan or {}).get("languages") or {}, "jload": db.jload}


def render(T, r, kind):
    from pathlib import Path
    css = (Path(__file__).resolve().parent.parent / "web" / "static" / "forms.css").read_text(encoding="utf-8")
    ctx = context(r, kind)
    ctx["css"] = css
    return T.get_template(KINDS[kind]["tpl"]).render(**ctx)
