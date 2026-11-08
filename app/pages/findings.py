import streamlit as st

from app import ai_view, ui
from core import db, grading, scanner

ui.page_header("점검 결과", "보안 점검 › 점검 결과")

scans = [s for s in db.list_scans() if s["status"] == "완료"]
if not scans:
    st.info("완료된 점검이 없습니다. ‘점검 실행’에서 먼저 점검하세요.")
    st.stop()

ids = [s["id"] for s in scans]
default = ids.index(st.session_state["scan_id"]) if st.session_state.get("scan_id") in ids else 0
scan_sel = st.selectbox("점검 선택", scans, index=default,
                        format_func=lambda s: f"{s['code']} · {s['device_name']} v{s['version']} · 등급 {s['grade']}")
st.session_state["scan_id"] = scan_sel["id"]
scan = db.get_scan(scan_sel["id"])
findings = db.findings_for_scan(scan["id"])

with st.container(key="card_summary"):
    g1, g2, g3 = st.columns([1, 4, 2])
    g1.markdown(ui.grade_box(scan["grade"], grading.GRADE_COLOR[scan["grade"]]), unsafe_allow_html=True)
    g2.markdown(f"**{scan['device_name']}** ({scan['device_code']}) · v{scan['version']} · {scan['source_name']}  \n"
                f"보안 점수 **{scan['score']}점** — {grading.GRADE_TEXT[scan['grade']]}  \n"
                f"<span class='mg-muted'>{scan['engine']} · 코드 파일 {scan['files_scanned']}개 · "
                f"{scan['finished_at'][:16].replace('T', ' ')}</span>", unsafe_allow_html=True)
    g3.markdown(f"취약점 **{len(findings)}건**<br>{ui.sev_badges(ui.counts_of(scan))}", unsafe_allow_html=True)
    st.caption(f"점수 산식: {grading.formula_text()}")

if not findings:
    st.success("탐지된 취약점이 없습니다.")
    st.stop()

sev_filter = st.multiselect("심각도", ui.SEV_ORDER, default=ui.SEV_ORDER,
                            format_func=lambda s: f"{s} ({ui.SEV_LABEL[s]})")
cache = st.session_state.setdefault("ai_cache", {})

for f in [x for x in findings if x["severity"] in sev_filter]:
    d = scanner.rule_detail(f["rule_id"])
    label = f"{ui.SEV_LABEL[f['severity']]} · {f['cwe']} {f['title']} — {f['file']}:{f['line']}"
    with st.expander(label):
        st.markdown(f'<span class="mg-pill" style="background:{ui.SEV_COLOR[f["severity"]]}">{f["severity"]}</span>'
                    f' <span class="mg-muted">규칙 {f["rule_id"]} · CVSS {d.get("cvss", "-")}</span>',
                    unsafe_allow_html=True)
        st.code(f["code"] or "(코드 조각 없음)", language="c")
        if d:
            st.markdown(f"**설명**  \n{d.get('description_ko', '')}")
            if d.get("device_impact_ko"):
                st.markdown(f"**의료기기 영향**  \n{d['device_impact_ko']}")
            rem = d.get("remediation_ko") or []
            if rem:
                st.markdown("**조치 방법**  \n" + "\n".join(f"- {r}" for r in rem))
            meta = " · ".join(x for x in [
                f"조치 기한: {d['deadline_ko']}" if d.get("deadline_ko") else "",
                f"참고: {d['fda_reference_ko']}" if d.get("fda_reference_ko") else ""] if x)
            if meta:
                st.caption(meta)
        else:
            st.caption(f["message"])

        st.markdown("---")
        if f["id"] in cache:
            st.markdown("**📘 AI 조치 매뉴얼**")
            ai_view.render(cache[f["id"]])
        elif st.button("📘 AI 조치 매뉴얼 찾기", key=f"ai_{f['id']}",
                       help="식약처·FDA 규제 문서에서 이 취약점의 관련 요구사항과 조치 방법을 찾아 근거와 함께 보여줍니다."):
            q = f"{f['title']} ({f['cwe']}) 취약점은 의료기기 사이버보안 요구사항상 어떻게 조치하고 문서화해야 하나요?"
            st.markdown("**📘 AI 조치 매뉴얼**")
            cache[f["id"]] = ai_view.ask(q)
            ai_view.render(cache[f["id"]])
