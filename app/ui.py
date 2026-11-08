"""공통 화면 부품: 스타일, 페이지 머리, 지표 카드, 심각도 배지, 등급 배지."""
import html

import streamlit as st

SEV_COLOR = {"Critical": "#C00000", "High": "#E36C09", "Medium": "#BF9000", "Low": "#808080"}
SEV_LABEL = {"Critical": "치명", "High": "높음", "Medium": "보통", "Low": "낮음"}
SEV_ORDER = ["Critical", "High", "Medium", "Low"]

ICONS = {  # 단순 선 아이콘 (Feather 계열 모양을 직접 그림)
    "device": '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
    "scan": '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/><circle cx="11" cy="14" r="2.5"/><path d="M13 16l2 2"/>',
    "alert": '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/>',
    "clip": '<rect x="6" y="4" width="12" height="17" rx="2"/><path d="M9 4h6v3H9z"/><path d="m9 13 2 2 4-4"/>',
    "book": '<path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20V3H6.5A2.5 2.5 0 0 0 4 5.5z"/><path d="M4 19.5A2.5 2.5 0 0 0 6.5 22H20v-5"/>',
}

CSS = """
<style>
:root { --mg-bg:#eef2f7; --mg-card:#ffffff; --mg-line:#e5e9f0; --mg-ink:#1f2937; --mg-sub:#6b7280; --mg-accent:#5b4fcf; }
.stApp { background: var(--mg-bg); }
.block-container { padding-top: 1.6rem; padding-bottom: 3rem; max-width: 1400px; }
section[data-testid="stSidebar"] { background:#ffffff; border-right:1px solid var(--mg-line); }
[data-testid="stSidebarNavLink"] { border-radius:8px; }
[data-testid="stSidebarNavLink"][aria-current="page"] { background:#ece9fb; }
[data-testid="stSidebarNavLink"][aria-current="page"] span { color:var(--mg-accent) !important; font-weight:600; }
.mg-head { background:var(--mg-card); border-radius:12px; padding:16px 22px; display:flex; justify-content:space-between;
           align-items:center; margin-bottom:18px; box-shadow:0 1px 2px rgba(16,24,40,.04); }
.mg-head h1 { font-size:1.35rem; margin:0; padding:0; color:var(--mg-ink); font-weight:700; }
.mg-crumb { color:var(--mg-sub); font-size:.9rem; }
.mg-card { background:var(--mg-card); border-radius:12px; padding:18px 20px; box-shadow:0 1px 2px rgba(16,24,40,.04); height:100%; }
.mg-card h3 { font-size:.98rem; margin:0 0 12px 0; color:var(--mg-ink); font-weight:700; }
.mg-kpi { display:flex; background:var(--mg-card); border-radius:12px; overflow:hidden; box-shadow:0 1px 2px rgba(16,24,40,.04); }
.mg-kpi .ic { width:92px; display:flex; align-items:center; justify-content:center; }
.mg-kpi .ic svg { width:34px; height:34px; stroke:#fff; fill:none; stroke-width:1.8; stroke-linecap:round; stroke-linejoin:round; }
.mg-kpi .tx { padding:14px 18px; }
.mg-kpi .num { font-size:1.6rem; font-weight:700; color:var(--mg-ink); line-height:1.1; }
.mg-kpi .lb { font-size:.85rem; color:var(--mg-sub); margin-top:2px; }
.mg-badge { display:inline-block; min-width:24px; padding:1px 6px; margin-right:3px; border-radius:4px;
            font-size:.78rem; font-weight:700; text-align:center; color:#fff; }
.mg-badge.zero { background:#eef0f3 !important; color:#9aa3af; }
.mg-pill { display:inline-block; padding:3px 12px; border-radius:6px; font-size:.8rem; font-weight:700; color:#fff; }
.mg-table { width:100%; border-collapse:collapse; font-size:.9rem; }
.mg-table th { background:#f3f5f9; color:#374151; font-weight:700; padding:10px 8px; text-align:center; }
.mg-table td { padding:10px 8px; border-bottom:1px solid var(--mg-line); text-align:center; color:#1f2937; }
.mg-row { display:flex; justify-content:space-between; align-items:center; padding:9px 2px; border-bottom:1px solid #f1f3f7; }
.mg-row:last-child { border-bottom:none; }
.mg-grade { display:inline-flex; align-items:center; justify-content:center; width:56px; height:56px; border-radius:12px;
            color:#fff; font-size:1.7rem; font-weight:800; }
.mg-cite { background:#f8fafc; border:1px solid var(--mg-line); border-left:4px solid var(--mg-accent);
           border-radius:8px; padding:10px 12px; margin:6px 0; font-size:.86rem; }
.mg-cite .src { font-weight:700; color:#374151; margin-bottom:4px; }
.mg-muted { color:var(--mg-sub); font-size:.85rem; }
/* key="card_..." 로 만든 컨테이너를 흰 카드로 */
[class*="st-key-card"] { background:var(--mg-card); border-radius:12px; padding:18px 20px;
                         box-shadow:0 1px 2px rgba(16,24,40,.04); }
</style>
"""


def setup():
    st.markdown(CSS, unsafe_allow_html=True)


def page_header(title, crumb=None):
    crumb = crumb or title
    st.markdown(f'<div class="mg-head"><h1>{html.escape(title)}</h1>'
                f'<div class="mg-crumb">홈 › {html.escape(crumb)}</div></div>', unsafe_allow_html=True)


def kpi(icon, color, number, label):
    return (f'<div class="mg-kpi"><div class="ic" style="background:{color}">'
            f'<svg viewBox="0 0 24 24">{ICONS[icon]}</svg></div>'
            f'<div class="tx"><div class="num">{number}</div><div class="lb">{html.escape(label)}</div></div></div>')


def sev_badges(counts: dict):
    out = []
    for s in SEV_ORDER:
        n = counts.get(s, 0) or 0
        cls = "mg-badge" if n else "mg-badge zero"
        out.append(f'<span class="{cls}" style="background:{SEV_COLOR[s]}" title="{SEV_LABEL[s]}">{n}</span>')
    return "".join(out)


def counts_of(row):
    return {"Critical": row.get("n_critical", 0), "High": row.get("n_high", 0),
            "Medium": row.get("n_medium", 0), "Low": row.get("n_low", 0)}


def status_pill(status):
    color = {"완료": "#22c55e", "진행중": "#3b82f6", "실패": "#ef4444"}.get(status, "#9ca3af")
    return f'<span class="mg-pill" style="background:{color}">{html.escape(status)}</span>'


def grade_box(grade, color):
    return f'<span class="mg-grade" style="background:{color}">{html.escape(grade or "-")}</span>'


def cite_card(i, c):
    excerpt = html.escape(c["text"][:420] + ("…" if len(c["text"]) > 420 else "")).replace("\n", "<br>")
    return (f'<div class="mg-cite"><div class="src">[{i}] {html.escape(c["org"])} · {html.escape(c["title"])}'
            f' · {c["page"]}쪽</div>{excerpt}</div>')
