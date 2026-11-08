import shutil
import time

import streamlit as st

from app import ui
from core import db, grading, scanner
from core.config import SAMPLES_DIR, UPLOADS

ui.page_header("점검 실행", "보안 점검 › 점검 실행")

SAMPLE_LABELS = {
    "secpump-vuln": "SecPump 무선 인슐린펌프 펌웨어 — 취약 버전",
    "secpump-vanilla": "SecPump 무선 인슐린펌프 펌웨어 — 정상 버전",
}

engine, engine_path = scanner.find_engine()
rules = scanner.rule_files()
if not engine:
    st.error("정적분석 엔진(OpenGrep 또는 Semgrep)이 설치되어 있지 않습니다. 관리자 › 시스템 설정을 확인하세요.")
    st.stop()

devices = db.list_devices()
if not devices:
    st.info("먼저 점검할 의료기기를 등록하세요.")
    if st.button("의료기기 등록하러 가기", type="primary"):
        st.switch_page("pages/devices.py")
    st.stop()

with st.container(key="card_scanform"):
    c1, c2 = st.columns([2, 1])
    dev = c1.selectbox("점검 대상 기기", devices, format_func=lambda d: f"{d['code']} · {d['name']}")
    version = c2.text_input("소프트웨어 버전", value="1.0.0")

    samples = sorted(p for p in SAMPLES_DIR.iterdir() if p.is_dir()) if SAMPLES_DIR.exists() else []
    mode = st.radio("소스코드 입력", ["소스 압축파일(.zip) 업로드", "시연용 샘플 사용"],
                    index=1 if samples else 0, horizontal=True)
    upload, sample = None, None
    if mode.startswith("소스"):
        upload = st.file_uploader("펌웨어·소프트웨어 소스코드 압축파일", type=["zip"])
    else:
        sample = st.selectbox("샘플", samples, format_func=lambda p: SAMPLE_LABELS.get(p.name, p.name))

    st.caption(f"점검 엔진: {engine} · 규칙 파일 {len(rules)}개 · 점수 산식: {grading.formula_text()}")
    go = st.button("점검 시작", type="primary", disabled=(upload is None and sample is None))

if go:
    source_name = upload.name if upload else SAMPLE_LABELS.get(sample.name, sample.name)
    scan_id = db.create_scan(dev["id"], version, source_name)
    with st.status("점검을 진행하고 있습니다…", expanded=True) as status:
        try:
            if upload:
                work = UPLOADS / f"scan_{scan_id}"
                work.mkdir(parents=True, exist_ok=True)
                zpath = work / "source.zip"
                zpath.write_bytes(upload.getvalue())
                st.write("압축 해제 중…")
                target = scanner.safe_extract_zip(zpath, work / "src")
            else:
                target = sample
            st.write(f"정적분석 실행 중 ({engine})…")
            t = time.time()
            findings, eng, nfiles = scanner.scan(target)
            score, grade = grading.score_findings(findings)
            db.finish_scan(scan_id, findings, score, grade, eng, nfiles)
            status.update(label=f"점검 완료 · {time.time() - t:.1f}초", state="complete")
        except Exception as e:
            db.finish_scan(scan_id, [], None, None, engine, 0, error=str(e))
            status.update(label="점검 실패", state="error")
            st.error(str(e))
            st.stop()

    scan = db.get_scan(scan_id)
    st.session_state["scan_id"] = scan_id
    with st.container(key="card_scanresult"):
        g1, g2 = st.columns([1, 5])
        g1.markdown(ui.grade_box(scan["grade"], grading.GRADE_COLOR[scan["grade"]]), unsafe_allow_html=True)
        g2.markdown(f"**{scan['code']}** · {scan['device_name']} v{scan['version']}  \n"
                    f"보안 점수 **{scan['score']}점** · {grading.GRADE_TEXT[scan['grade']]}  \n"
                    f"코드 파일 {scan['files_scanned']}개 점검 · 취약점 {len(findings)}건 "
                    f"{ui.sev_badges(ui.counts_of(scan))}", unsafe_allow_html=True)
        if st.button("점검 결과 자세히 보기 →", type="primary"):
            st.switch_page("pages/findings.py")
