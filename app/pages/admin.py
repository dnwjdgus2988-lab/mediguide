import pandas as pd
import streamlit as st

from app import ui
from core import config, db, llm, rag, scanner

ui.page_header("시스템 설정", "관리자 › 시스템 설정")

engine, path = scanner.find_engine()
rules = scanner.rule_files()
c1, c2, c3 = st.columns(3)
with c1.container(key="card_engine"):
    st.markdown("**정적분석 엔진**")
    st.write(f"{engine or '없음'}")
    st.caption(path or "OpenGrep 또는 Semgrep 설치 필요")
    st.caption(f"규칙 파일 {len(rules)}개: " + ", ".join(r.name for r in rules))
with c2.container(key="card_ai"):
    st.markdown("**AI 답변**")
    st.write(llm.provider_label())
    st.caption("연결됨 ✅" if llm.available() else "연결 안 됨 — 검색 결과만 표시")
    st.caption("전환: 환경변수 MG_LLM = ollama | bedrock | none")
with c3.container(key="card_db"):
    s = db.stats()
    st.markdown("**저장소**")
    st.write(f"기기 {s['devices']} · 점검 {s['scans_done']} · 취약점 {s['findings']}")
    st.caption(str(config.DB_PATH))

st.write("")
with st.container(key="card_index"):
    st.markdown("**규제 문서 검색 색인**")
    info = rag.index_info()
    if info:
        st.caption(f"{info['chunks']:,}개 구간 · 문서 {len(info['docs'])}종 (구판 가이드라인은 제외)")
        st.dataframe(pd.DataFrame(info["docs"]).rename(columns={"org": "기관", "title": "문서", "chunks": "구간 수"}),
                     hide_index=True, width="stretch")
    else:
        st.caption("색인 없음")
    if st.button("색인 다시 만들기"):
        bar = st.progress(0.0, text="준비 중…")
        rag.build_index(progress=lambda r, name: bar.progress(r, text=name))
        rag.reset_cache()
        st.success("색인을 다시 만들었습니다.")
        st.rerun()
