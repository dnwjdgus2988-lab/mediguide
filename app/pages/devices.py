import html

import streamlit as st

from app import ui
from core import db

ui.page_header("의료기기 관리", "의료기기 › 의료기기 관리")

CATEGORIES = ["주입기기(인슐린·수액 펌프)", "생체신호 모니터", "체외진단기기", "영상기기",
              "디지털의료기기 소프트웨어", "웨어러블", "기타"]

with st.expander("➕ 새 의료기기 등록", expanded=not db.list_devices()):
    with st.form("add_device", clear_on_submit=True):
        c1, c2 = st.columns(2)
        name = c1.text_input("기기명 *", placeholder="예: 무선 인슐린펌프")
        model = c2.text_input("모델명", placeholder="예: SP-100")
        maker = c1.text_input("제조사", placeholder="예: (주)○○메디칼")
        category = c2.selectbox("분류", CATEGORIES)
        desc = st.text_area("설명", placeholder="통신 방식(BLE 등), 주요 기능 등", height=80)
        if st.form_submit_button("등록", type="primary"):
            if not name.strip():
                st.error("기기명을 입력하세요.")
            else:
                code = db.add_device(name.strip(), model.strip(), maker.strip(), category, desc.strip())
                st.success(f"등록 완료: {code} · {name}")
                st.rerun()

devices = db.list_devices()
if not devices:
    st.info("등록된 기기가 없습니다. 위에서 먼저 기기를 등록하세요.")
else:
    trs = "".join(
        f"<tr><td>{d['code']}</td><td><b>{html.escape(d['name'])}</b></td><td>{html.escape(d['model'] or '-')}</td>"
        f"<td>{html.escape(d['maker'] or '-')}</td><td>{html.escape(d['category'] or '-')}</td>"
        f"<td>{d['scan_count']}</td><td>{(d['last_scan'] or '-')[:16].replace('T', ' ')}</td></tr>"
        for d in devices)
    st.markdown(
        f'<div class="mg-card"><h3>등록 장비 ({len(devices)})</h3><table class="mg-table">'
        f'<tr><th>기기 ID</th><th>기기명</th><th>모델</th><th>제조사</th><th>분류</th><th>점검 수</th>'
        f'<th>최근 점검</th></tr>{trs}</table></div>', unsafe_allow_html=True)
