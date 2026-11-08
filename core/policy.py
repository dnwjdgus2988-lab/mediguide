"""정책값 저장소. 관리자 화면에서 바꾸면 이후 계산부터 반영된다(발행된 리포트는 발행 당시 값 유지)."""
import time

from core import db

_cache = {"t": 0.0, "v": {}}


def _defaults():
    # (키, 설명, 값, 분류, 근거 기관, 근거 조항)
    from core.checklist import QUESTIONS, COND_TEXT
    rows = []
    for qid, _a, _t, pts, _e, basis, half, cond, legal in QUESTIONS:
        reg = cond == "SECTION_524B"
        rows.append((f"checklist.applicability.{qid}", f"체크리스트 {qid} 적용조건 — {COND_TEXT[cond]}", cond,
                     "규정" if reg else "정책", "FD&C Act" if reg else "메디가이드 내부 기준",
                     "§524B(a)·(c)" if reg else "적용조건 자동판정"))
    for qid, _a, _t, pts, _e, basis, half, cond, legal in QUESTIONS:
        rows.append((f"checklist.points.{qid}", f"체크리스트 {qid} 배점", str(pts), "정책", "메디가이드 내부 기준",
                     f"FDA Premarket Cybersecurity Guidance {basis}"))
    rows += [
        ("checklist.half_credit_ratio", "「예」인데 연계 증빙이 없을 때 인정 비율", "0.5", "정책", "메디가이드 내부 기준", "배점정책"),
        ("grade.band.A", "A 등급 하한 (문서 충족률)", "90", "정책", "메디가이드 내부 기준", "등급 구간"),
        ("grade.band.B", "B 등급 하한 (문서 충족률)", "80", "정책", "메디가이드 내부 기준", "등급 구간"),
        ("grade.band.C", "C 등급 하한 (문서 충족률)", "70", "정책", "메디가이드 내부 기준", "등급 구간"),
        ("grade.cap.critical_high", "Critical·High 취약점이 있을 때 등급 상한", "D", "정책", "메디가이드 내부 기준", "상한정책"),
        ("grade.cap.medium", "Medium 취약점이 있을 때 등급 상한 (빈 값 = 상한 없음)", "", "정책", "메디가이드 내부 기준", "상한정책"),
        ("severity.cvss.critical", "Critical 구간 (CVSS)", "9.0-10.0", "표준", "FIRST", "CVSS v3.1 Specification §5"),
        ("severity.cvss.high", "High 구간 (CVSS)", "7.0-8.9", "표준", "FIRST", "CVSS v3.1 Specification §5"),
        ("severity.cvss.medium", "Medium 구간 (CVSS)", "4.0-6.9", "표준", "FIRST", "CVSS v3.1 Specification §5"),
        ("severity.cvss.low", "Low 구간 (CVSS)", "0.1-3.9", "표준", "FIRST", "CVSS v3.1 Specification §5"),
        ("deadline.Critical", "Critical 조치 시급성", "즉시 — 인허가 신청 전 필수 해결", "정책", "메디가이드 내부 기준", "조치 시급성"),
        ("deadline.High", "High 조치 시급성", "즉시 — 인허가 신청 전 필수 해결", "정책", "메디가이드 내부 기준", "조치 시급성"),
        ("deadline.Medium", "Medium 조치 시급성", "차기 배포 버전 내 해결 권고", "정책", "메디가이드 내부 기준", "조치 시급성"),
        ("deadline.Low", "Low 조치 시급성", "정기 유지보수 시 검토", "정책", "메디가이드 내부 기준", "조치 시급성"),
        ("scan.exclude_paths", "정적분석 집계 제외 경로(서드파티·빌드)",
         "venv,site-packages,node_modules,.git,build,dist,out,third_party,external,vendor,deps,Middlewares,Drivers,CMSIS,__pycache__",
         "정책", "메디가이드 내부 기준", "분석 범위"),
        ("scan.ruleset_label", "적용 룰셋 표시 이름", "CWE Top 25 + 의료기기 펌웨어 v2.0", "정책", "메디가이드 내부 기준", "룰셋"),
        ("submission.fda_paths", "§524B 적용 제출 경로", "510(k),De Novo,PMA,PDP,HDE", "규정", "FD&C Act", "§524B(a)"),
        ("evidence.max_mb", "증빙 파일 최대 크기(MB)", "50", "정책", "메디가이드 내부 기준", "업로드 제한"),
        ("evidence.allowed_ext", "증빙 허용 형식 (형식검사 F1)", "pdf,docx,xlsx,json,xml,spdx,txt,md,zip", "정책", "메디가이드 내부 기준", "형식 준수성"),
        ("ai.top_k", "AI 매뉴얼 검색 근거 개수", "5", "정책", "메디가이드 내부 기준", "근거 인용형 답변"),
        ("ai.per_doc", "문서당 최대 근거 수", "2", "정책", "메디가이드 내부 기준", "근거 인용형 답변"),
    ]
    return rows


def seed():
    have = {r["key"] for r in db.q("SELECT key FROM policies")}
    for key, desc, val, cat, org, ref in _defaults():
        if key not in have:
            db.insert("policies", {"key": key, "description": desc, "value": val, "category": cat,
                                   "basis_org": org, "basis_ref": ref})
    reset()


def reset():
    _cache["t"] = 0.0


def get(key, default=""):
    if time.time() - _cache["t"] > 5:
        _cache["v"] = {r["key"]: r["value"] for r in db.q("SELECT key, value FROM policies")}
        _cache["t"] = time.time()
    v = _cache["v"].get(key)
    return default if v is None else v


def set_value(key, value, user):
    db.run("UPDATE policies SET value=?, updated_by=?, updated_at=? WHERE key=?", (value, user, db.now(), key))
    reset()


def snapshot():
    """리포트 발행 시점 정책값 (재현용)."""
    return {r["key"]: r["value"] for r in db.q("SELECT key, value FROM policies")}
