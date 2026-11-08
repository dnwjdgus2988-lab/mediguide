import streamlit as st

from app import ui
from core import db, report

ui.page_header("결과 리포트", "리포트 › 결과 리포트")

scans = [s for s in db.list_scans() if s["status"] == "완료"]
if not scans:
    st.info("완료된 점검이 없습니다.")
    st.stop()

ids = [s["id"] for s in scans]
default = ids.index(st.session_state["scan_id"]) if st.session_state.get("scan_id") in ids else 0
sel = st.selectbox("점검 선택", scans, index=default,
                   format_func=lambda s: f"{s['code']} · {s['device_name']} v{s['version']} · 등급 {s['grade']}")
scan = db.get_scan(sel["id"])
findings = db.findings_for_scan(scan["id"])
ai_cache = st.session_state.get("ai_cache", {})
n_ai = sum(1 for f in findings if f["id"] in ai_cache)

with st.container(key="card_report"):
    st.markdown("**리포트 구성**")
    st.markdown("1. 표지 (기기·점검 정보)  \n2. 종합 결과 (등급·점수·심각도별 건수·산식)  \n"
                "3. 취약점 목록  \n4. 취약점 상세 및 조치 방법 (+ AI 조치 매뉴얼 근거)  \n5. 유의사항")
    st.caption(f"AI 조치 매뉴얼을 받아 둔 취약점 {n_ai}/{len(findings)}건이 리포트에 함께 실립니다. "
               f"(점검 결과 화면에서 ‘AI 조치 매뉴얼 찾기’를 누른 항목)")
    if st.button("PDF 리포트 만들기", type="primary"):
        with st.spinner("리포트를 만드는 중…"):
            path = report.build(scan, findings, ai_cache)
        st.session_state["report_path"] = str(path)

    path = st.session_state.get("report_path")
    if path and scan["code"] in path:
        with open(path, "rb") as fh:
            st.download_button("⬇ PDF 내려받기", fh.read(), file_name=path.split("\\")[-1].split("/")[-1],
                               mime="application/pdf")
