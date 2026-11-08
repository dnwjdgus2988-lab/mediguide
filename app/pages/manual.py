import streamlit as st

from app import ai_view, ui
from core import llm, rag

ui.page_header("AI 매뉴얼 검색", "AI 매뉴얼 › 매뉴얼 검색")

info = rag.index_info()
if not info:
    st.warning("규제 문서 검색 색인이 아직 없습니다.")
    if st.button("색인 만들기", type="primary"):
        with st.spinner("규제 문서를 읽어 색인을 만드는 중…"):
            rag.build_index()
            rag.reset_cache()
        st.rerun()
    st.stop()

with st.container(key="card_opts"):
    c1, c2, c3 = st.columns([1.2, 1.4, 2.4])
    org_label = c1.selectbox("검색 범위", ["전체", "식약처", "FDA"])
    expand = c2.toggle("FDA 영문 문서도 함께 검색", value=False,
                       help="한국어 질문을 영어 검색어로 바꿔 FDA 문서까지 찾습니다 (답변이 조금 느려집니다).")
    c3.markdown(f"<div class='mg-muted' style='padding-top:8px'>문서 {len(info['docs'])}종 · "
                f"{info['chunks']:,}개 구간 색인됨 · {llm.provider_label()}</div>", unsafe_allow_html=True)

EXAMPLES = [
    "SBOM은 어떤 형식으로 작성해야 하나요?",
    "사이버보안 허가 신청 시 제출해야 하는 자료는 무엇인가요?",
    "의료기기 소프트웨어 업데이트·패치는 어떻게 관리해야 하나요?",
    "무선 통신(BLE) 기기의 인증·암호화 요구사항은?",
]
history = st.session_state.setdefault("chat", [])

if not history:
    st.markdown("**이런 질문을 해 보세요**")
    cols = st.columns(len(EXAMPLES))
    for col, ex in zip(cols, EXAMPLES):
        if col.button(ex, key=f"ex_{ex}", width="stretch"):
            st.session_state["pending_q"] = ex
            st.rerun()

for turn in history:
    with st.chat_message("user"):
        st.markdown(turn["q"])
    with st.chat_message("assistant"):
        ai_view.render(turn["result"])

q = st.chat_input("규제·인허가 관련 질문을 입력하세요") or st.session_state.pop("pending_q", None)
if q:
    with st.chat_message("user"):
        st.markdown(q)
    with st.chat_message("assistant"):
        result = ai_view.ask(q, org=None if org_label == "전체" else org_label, expand_en=expand)
        ai_view.render(result)
    history.append({"q": q, "result": result})

if history and st.button("대화 지우기"):
    st.session_state["chat"] = []
    st.rerun()
