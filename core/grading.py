"""보안 점수(100점 만점)와 A~D 등급 산정. 산식은 화면·리포트에 그대로 공개한다."""

PENALTY = {"Critical": 25, "High": 15, "Medium": 5, "Low": 1}
GRADES = [(90, "A"), (75, "B"), (60, "C"), (0, "D")]
GRADE_TEXT = {
    "A": "양호 — 인허가 제출 전 확인 수준",
    "B": "보통 — 일부 보완 후 제출 권장",
    "C": "미흡 — 주요 취약점 조치 필요",
    "D": "위험 — 제출 전 반드시 조치 필요",
}
GRADE_COLOR = {"A": "#16a34a", "B": "#2563eb", "C": "#d97706", "D": "#dc2626"}


def score_findings(findings):
    penalty = sum(PENALTY.get(f["severity"], 0) for f in findings)
    score = max(0, 100 - penalty)
    grade = next(g for cut, g in GRADES if score >= cut)
    return score, grade


def formula_text():
    parts = ", ".join(f"{k} -{v}" for k, v in PENALTY.items())
    return f"100점에서 취약점마다 감점({parts}) · A ≥90, B ≥75, C ≥60, D <60"
