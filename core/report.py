"""점검 결과 PDF 리포트 (fpdf2, 한글 글꼴 내장)."""
from datetime import datetime

from fpdf import FPDF
from fpdf.enums import XPos, YPos

from core import config, grading
from core.scanner import rule_detail

SEV_KO = {"Critical": "치명", "High": "높음", "Medium": "보통", "Low": "낮음"}
SEV_RGB = {"Critical": (192, 0, 0), "High": (227, 108, 9), "Medium": (191, 144, 0), "Low": (128, 128, 128)}
NL = dict(new_x=XPos.LMARGIN, new_y=YPos.NEXT)


class Report(FPDF):
    def __init__(self, scan):
        super().__init__(format="A4")
        self.scan = scan
        reg = config.first_existing(config.FONT_CANDIDATES)
        bold = config.first_existing(config.FONT_BOLD_CANDIDATES) or reg
        if not reg:
            raise RuntimeError("리포트용 한글 글꼴을 찾을 수 없습니다 (MG_FONT 설정 필요).")
        self.add_font("KR", "", reg)
        self.add_font("KR", "B", bold)
        self.set_auto_page_break(True, margin=18)
        self.set_margins(18, 18, 18)

    def header(self):
        if self.page_no() == 1:
            return
        self.set_font("KR", "", 8)
        self.set_text_color(120)
        self.cell(0, 6, f"{config.SERVICE_NAME} 보안 점검 결과 리포트 · {self.scan['code']}", **NL)
        self.set_text_color(0)

    def footer(self):
        self.set_y(-12)
        self.set_font("KR", "", 8)
        self.set_text_color(140)
        self.cell(0, 6, f"{self.page_no()} / {{nb}}", align="C")
        self.set_text_color(0)

    # 도우미
    def h1(self, text):
        self.set_font("KR", "B", 13)
        self.set_fill_color(238, 242, 247)
        self.cell(0, 9, f"  {text}", fill=True, **NL)
        self.ln(2)

    def para(self, text, size=9.5, bold=False, color=(0, 0, 0)):
        self.set_font("KR", "B" if bold else "", size)
        self.set_text_color(*color)
        self.multi_cell(0, 5.4, text, **NL)
        self.set_text_color(0)


def build(scan, findings, ai_results=None):
    """ai_results: {finding_id: {"answer":..., "hits":[...], "not_found":bool}} (선택)"""
    ai_results = ai_results or {}
    pdf = Report(scan)
    pdf.alias_nb_pages()
    pdf.add_page()

    # ── 표지 ──
    pdf.set_font("KR", "B", 20)
    pdf.ln(18)
    pdf.cell(0, 12, "의료기기 소프트웨어 보안 점검 결과 리포트", align="C", **NL)
    pdf.set_font("KR", "", 11)
    pdf.set_text_color(100)
    pdf.cell(0, 8, f"{config.SERVICE_NAME} · {config.SERVICE_TAGLINE}", align="C", **NL)
    pdf.set_text_color(0)
    pdf.ln(10)
    rows = [("점검 ID", scan["code"]), ("대상 기기", f"{scan['device_name']} ({scan['device_code']})"),
            ("모델 / 제조사", f"{scan.get('model') or '-'} / {scan.get('maker') or '-'}"),
            ("소프트웨어 버전", scan["version"] or "-"), ("점검 소스", scan["source_name"] or "-"),
            ("점검 엔진", f"{scan['engine']} (규칙 기반 정적분석)"),
            ("점검 일시", (scan["finished_at"] or "")[:16].replace("T", " ")),
            ("리포트 생성", datetime.now().strftime("%Y-%m-%d %H:%M"))]
    pdf.set_font("KR", "", 10)
    with pdf.table(col_widths=(35, 105), text_align=("LEFT", "LEFT"), line_height=7,
                   headings_style=None, first_row_as_headings=False) as t:
        for k, v in rows:
            r = t.row()
            r.cell(k)
            r.cell(v)

    # ── 1. 종합 결과 ──
    pdf.ln(8)
    pdf.h1("1. 종합 결과")
    color = tuple(int(grading.GRADE_COLOR[scan["grade"]][i:i + 2], 16) for i in (1, 3, 5))
    pdf.set_font("KR", "B", 28)
    pdf.set_text_color(*color)
    pdf.cell(22, 16, scan["grade"], align="C")
    pdf.set_text_color(0)
    pdf.set_font("KR", "B", 12)
    pdf.cell(0, 8, f"보안 점수 {scan['score']}점 — {grading.GRADE_TEXT[scan['grade']]}", **NL)
    pdf.set_x(40)
    pdf.set_font("KR", "", 9.5)
    counts = {"Critical": scan["n_critical"], "High": scan["n_high"], "Medium": scan["n_medium"], "Low": scan["n_low"]}
    pdf.cell(0, 8, "취약점 " + " · ".join(f"{SEV_KO[k]} {v}건" for k, v in counts.items())
             + f" (총 {sum(counts.values())}건, 코드 파일 {scan['files_scanned']}개)", **NL)
    pdf.para(f"점수 산식: {grading.formula_text()}", size=8.5, color=(110, 110, 110))

    # ── 2. 취약점 목록 ──
    pdf.ln(4)
    pdf.h1("2. 취약점 목록")
    if not findings:
        pdf.para("탐지된 취약점이 없습니다.")
    else:
        pdf.set_font("KR", "", 8.5)
        with pdf.table(col_widths=(8, 14, 20, 58, 60), line_height=6, text_align="LEFT") as t:
            h = t.row()
            for x in ("No", "심각도", "CWE", "항목", "위치"):
                h.cell(x)
            for i, f in enumerate(findings, 1):
                r = t.row()
                r.cell(str(i))
                r.cell(SEV_KO.get(f["severity"], f["severity"]))
                r.cell(f["cwe"] or "-")
                r.cell(f["title"])
                r.cell(f"{f['file']}:{f['line']}")

    # ── 3. 취약점 상세 및 조치 ──
    if findings:
        pdf.add_page()
        pdf.h1("3. 취약점 상세 및 조치 방법")
        for i, f in enumerate(findings, 1):
            d = rule_detail(f["rule_id"])
            pdf.set_text_color(*SEV_RGB.get(f["severity"], (0, 0, 0)))
            pdf.para(f"[{i}] {SEV_KO.get(f['severity'])} · {f['cwe']} {f['title']}", size=10.5, bold=True,
                     color=SEV_RGB.get(f["severity"], (0, 0, 0)))
            pdf.para(f"위치: {f['file']}:{f['line']}   규칙: {f['rule_id']}   CVSS: {d.get('cvss', '-')}",
                     size=8.5, color=(90, 90, 90))
            if f["code"]:
                pdf.set_fill_color(246, 247, 249)
                pdf.set_font("KR", "", 8)
                pdf.multi_cell(0, 4.6, f["code"][:600], fill=True, **NL)
            if d.get("description_ko"):
                pdf.para("설명: " + d["description_ko"])
            if d.get("device_impact_ko"):
                pdf.para("의료기기 영향: " + d["device_impact_ko"])
            for r in d.get("remediation_ko") or []:
                pdf.para("  - " + r)
            if d.get("deadline_ko"):
                pdf.para("조치 기한: " + d["deadline_ko"], size=9, bold=True)
            ai = ai_results.get(f["id"])
            if ai and ai.get("answer") and not ai.get("not_found"):
                pdf.para("AI 조치 매뉴얼 (규제 문서 근거):", size=9.5, bold=True, color=(91, 79, 207))
                pdf.para(ai["answer"], size=9)
                for j, h in enumerate(ai["hits"], 1):
                    pdf.para(f"  [{j}] {h['org']} · {h['title']} · {h['page']}쪽", size=8, color=(100, 100, 100))
            pdf.ln(3)

    # ── 4. 유의사항 ──
    pdf.ln(2)
    pdf.h1("4. 유의사항")
    pdf.para("본 리포트는 규칙 기반 정적분석 결과와 공개 규제 문서 검색을 바탕으로 자동 생성된 참고 자료입니다. "
             "정적분석은 오탐·미탐이 있을 수 있으며, 실제 인허가 제출 전에는 반드시 보안·인허가 전문가의 검토와 "
             "동적 시험(침투 시험 등)을 병행해야 합니다.", size=9, color=(80, 80, 80))

    out = config.REPORTS / f"{scan['code']}_report.pdf"
    pdf.output(str(out))
    return out
