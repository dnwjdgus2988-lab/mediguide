import html

import plotly.graph_objects as go
import streamlit as st

from app import ui
from core import db

ui.page_header("대시보드")
s = db.stats()

c1, c2, c3, c4 = st.columns(4)
c1.markdown(ui.kpi("device", "#2b88d8", s["devices"], "등록 장비"), unsafe_allow_html=True)
c2.markdown(ui.kpi("scan", "#2f6fa3", s["scans_done"], "완료 점검"), unsafe_allow_html=True)
c3.markdown(ui.kpi("alert", "#c0453a", s["findings"], "발견 취약점"), unsafe_allow_html=True)
c4.markdown(ui.kpi("clip", "#d4932a", s["scans_running"], "진행 중 점검"), unsafe_allow_html=True)
st.write("")

left, right = st.columns([1.15, 1])
with left:
    with st.container(key="card_sev"):
        st.markdown('<h3 style="font-size:.98rem;margin:0 0 4px 0">취약점 심각도 분포</h3>', unsafe_allow_html=True)
        sev = s["severity"]
        total = sum(sev.values())
        if total:
            fig = go.Figure(go.Pie(
                labels=[f"{k} ({ui.SEV_LABEL[k]})" for k in ui.SEV_ORDER],
                values=[sev[k] for k in ui.SEV_ORDER], hole=0.66, sort=False,
                marker=dict(colors=[ui.SEV_COLOR[k] for k in ui.SEV_ORDER]),
                textinfo="none", hovertemplate="%{label}: %{value}건 (%{percent})<extra></extra>"))
            fig.update_layout(
                height=250, margin=dict(l=0, r=0, t=0, b=0), showlegend=True,
                legend=dict(orientation="v", x=1.02, y=0.5, font=dict(size=13)),
                annotations=[dict(text=f"<b>{total}</b><br>취약점", x=0.5, y=0.5, showarrow=False, font=dict(size=18))],
                paper_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})
        else:
            st.caption("아직 점검 결과가 없습니다. ‘점검 실행’에서 첫 점검을 해 보세요.")

with right:
    rows = db.top_risky_devices(5)
    body = "".join(
        f'<div class="mg-row"><div><b>{html.escape(r["name"])}</b> '
        f'<span class="mg-muted">{r["code"]} · 등급 {r["grade"]}</span></div>'
        f'<div>{ui.sev_badges(ui.counts_of(r))} <span class="mg-muted">총 '
        f'{r["n_critical"] + r["n_high"] + r["n_medium"] + r["n_low"]}건</span></div></div>'
        for r in rows) or '<div class="mg-muted">점검이 끝난 기기가 없습니다.</div>'
    st.markdown(f'<div class="mg-card"><h3>고위험 기기 Top 5</h3>{body}</div>', unsafe_allow_html=True)

st.write("")
scans = db.list_scans(limit=8)
trs = "".join(
    f"<tr><td>{r['code']}</td><td>{html.escape(r['device_name'])}</td><td>{html.escape(r['version'] or '-')}</td>"
    f"<td>{r['started_at'][:16].replace('T', ' ')}</td><td>{ui.sev_badges(ui.counts_of(r))}</td>"
    f"<td>{r['grade'] or '-'}</td><td>{ui.status_pill(r['status'])}</td></tr>"
    for r in scans)
table = (f'<table class="mg-table"><tr><th>점검 ID</th><th>대상 장비</th><th>버전</th><th>점검 일시</th>'
         f'<th>심각도</th><th>등급</th><th>상태</th></tr>{trs}</table>') if scans else \
    '<div class="mg-muted">최근 점검이 없습니다.</div>'
st.markdown(f'<div class="mg-card"><h3>최근 점검</h3>{table}</div>', unsafe_allow_html=True)
