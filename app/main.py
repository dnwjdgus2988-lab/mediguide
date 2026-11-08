"""메디가이드 진입점:  streamlit run app/main.py"""
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st  # noqa: E402

from app import ui  # noqa: E402
from core import config, db, llm  # noqa: E402

st.set_page_config(page_title=f"{config.SERVICE_NAME} — {config.SERVICE_TAGLINE}", page_icon="🩺", layout="wide")
db.init_db()
ui.setup()


@st.cache_resource
def _warm():
    """첫 질문 대기를 줄이려고 로컬 AI 모델을 백그라운드에서 미리 올린다 (프로세스당 1회)."""
    threading.Thread(target=llm.warm_up, daemon=True).start()
    return True


_warm()

logo = ROOT / "app" / "assets" / "logo.png"
if logo.exists():
    st.logo(str(logo), size="large")

pages = {
    "": [st.Page("pages/dashboard.py", title="대시보드", icon=":material/dashboard:", default=True)],
    "의료기기": [st.Page("pages/devices.py", title="의료기기 관리", icon=":material/devices:")],
    "보안 점검": [st.Page("pages/scan.py", title="점검 실행", icon=":material/policy:"),
                st.Page("pages/findings.py", title="점검 결과", icon=":material/bug_report:")],
    "AI 매뉴얼": [st.Page("pages/manual.py", title="매뉴얼 검색", icon=":material/menu_book:")],
    "리포트": [st.Page("pages/report.py", title="결과 리포트", icon=":material/description:")],
    "관리자": [st.Page("pages/admin.py", title="시스템 설정", icon=":material/settings:")],
}
nav = st.navigation(pages)

with st.sidebar:
    st.markdown("---")
    st.caption(f"{config.SERVICE_NAME} v0.1 · 무한루프")
    st.caption(f"AI: {llm.provider_label()}")

nav.run()
