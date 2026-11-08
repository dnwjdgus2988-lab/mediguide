"""메디가이드 전역 설정. 환경변수로 덮어쓸 수 있다 (EC2 배포 시 .env 사용)."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# ── 데이터 위치 ──────────────────────────────────────────────
# data_local/ 은 Git에 올리지 않는 로컬 전용 폴더(규칙·규제원문·시연 펌웨어).
DATA_LOCAL = Path(os.getenv("MG_DATA_DIR", ROOT / "data_local"))
RULES_DIR = Path(os.getenv("MG_RULES_DIR", DATA_LOCAL / "rules"))
RULE_MESSAGES = RULES_DIR / "rule-messages.ko.json"
REGULATIONS_DIR = Path(os.getenv("MG_REG_DIR", DATA_LOCAL / "regulations"))
SAMPLES_DIR = DATA_LOCAL / "samples"

# storage/ 는 실행 중 생기는 파일(DB, 업로드, 검색 색인, 리포트).
STORAGE = Path(os.getenv("MG_STORAGE_DIR", ROOT / "storage"))
UPLOADS = STORAGE / "uploads"
REPORTS = STORAGE / "reports"
DB_PATH = STORAGE / "mediguide.db"
INDEX_PATH = STORAGE / "manual_index.pkl"

# ── AI 설정 ─────────────────────────────────────────────────
# MG_LLM: ollama(로컬·온프레미스) | bedrock(대회 제공 AWS) | none(검색 결과만 표시)
LLM_PROVIDER = os.getenv("MG_LLM", "ollama")
OLLAMA_URL = os.getenv("MG_OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("MG_OLLAMA_MODEL", "exaone3.5:7.8b")
BEDROCK_MODEL = os.getenv("MG_BEDROCK_MODEL", "")  # 운영진 안내 모델 ID로 설정
BEDROCK_REGION = os.getenv("AWS_REGION", "ap-northeast-2")

# ── 리포트용 한글 글꼴 (Windows → 맑은 고딕, Linux → 나눔고딕) ──
FONT_CANDIDATES = [
    os.getenv("MG_FONT", ""),
    "C:/Windows/Fonts/malgun.ttf",
    "/usr/share/fonts/truetype/nanum/NanumGothic.ttf",
    "/usr/share/fonts/nanum/NanumGothic.ttf",
]
FONT_BOLD_CANDIDATES = [
    os.getenv("MG_FONT_BOLD", ""),
    "C:/Windows/Fonts/malgunbd.ttf",
    "/usr/share/fonts/truetype/nanum/NanumGothicBold.ttf",
    "/usr/share/fonts/nanum/NanumGothicBold.ttf",
]

SERVICE_NAME = "메디가이드"
SERVICE_TAGLINE = "의료기기 보안 점검 · AI 조치 매뉴얼 검색"

for _d in (STORAGE, UPLOADS, REPORTS):
    _d.mkdir(parents=True, exist_ok=True)


def first_existing(paths):
    for p in paths:
        if p and Path(p).exists():
            return str(p)
    return None
