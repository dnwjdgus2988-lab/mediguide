"""AI 근거 인용 답변을 화면에 그린다 (점검 결과 · 매뉴얼 검색 공용)."""
import streamlit as st

from app import ui
from core import llm, rag


def ask(question, org=None, expand_en=False, k=5):
    """검색 → 답변 생성(스트리밍 표시) → 근거 검증 후 최종본으로 교체. 결과 dict를 돌려준다."""
    extra = ()
    if expand_en and org != "식약처":
        with st.spinner("FDA 영문 문서용 검색어를 만드는 중…"):
            en = llm.expand_query_en(question)
        if en:
            extra = (en,)
    hits = rag.search(question, k=k, org=org, extra_queries=extra)

    box = st.empty()
    if not llm.available():
        result = {"answer": None, "hits": hits, "not_found": not hits}
    else:
        acc = ""
        try:
            for piece in llm.answer_stream(question, hits):
                acc += piece
                box.markdown(acc + " ▌")
            final, nf = llm.finalize(acc, hits)
        except Exception as e:  # 모델 서버 오류 등
            final, nf = f"AI 답변 생성 중 오류가 발생했습니다: {e}", False
        result = {"answer": final, "hits": hits, "not_found": nf}
    box.empty()
    return result


def render(result):
    if result["answer"] is None:
        st.info("AI 답변이 꺼져 있어 관련 근거 구간만 보여드립니다.")
    elif result["not_found"]:
        st.warning(result["answer"])
    else:
        st.markdown(result["answer"])
    hits = result["hits"]
    if hits and not result["not_found"]:
        with st.expander(f"근거 원문 보기 ({len(hits)}건)", expanded=result["answer"] is None):
            st.markdown("".join(ui.cite_card(i, h) for i, h in enumerate(hits, 1)), unsafe_allow_html=True)
    elif hits and result["not_found"]:
        with st.expander("검색은 됐지만 답을 뒷받침하지 못한 구간 보기"):
            st.markdown("".join(ui.cite_card(i, h) for i, h in enumerate(hits, 1)), unsafe_allow_html=True)
    st.caption("※ 근거 문서를 바탕으로 한 참고용 안내입니다. 최종 판단은 인허가 전문가 검토가 필요합니다.")
