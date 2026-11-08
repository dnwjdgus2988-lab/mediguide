"""규제 문서(매뉴얼) 색인과 검색.

- PDF/TXT를 쪽 단위로 읽어 겹치는 구간으로 나눈다(쪽 번호를 근거로 보존).
- 한국어는 Kiwi 형태소 분석, 영어는 소문자 단어로 토큰화한다.
- BM25로 순위를 매긴다. (EC2에서는 Bedrock 임베딩을 더해 하이브리드로 확장 가능)
"""
import math
import pickle
import re
from collections import Counter, defaultdict
from pathlib import Path

import fitz  # PyMuPDF

from core.config import INDEX_PATH, REGULATIONS_DIR

# 파일명 → 화면에 보여줄 문서 정보. superseded=True 인 구판은 색인하지 않는다.
DOCS = {
    "mfds_15625.pdf": ("식약처", "의료기기의 사이버보안 허가·심사 가이드라인 (안내서-0995-05, 2025.1.10.)", False),
    "secguide_2025.pdf": ("식약처", "디지털의료기기 전자적 침해행위 보안지침 (2025.11.)", False),
    "mfds_15653.pdf": ("식약처", "디지털의료기기소프트웨어 허가·심사 가이드라인 (안내서-1425-01, 2025.5.)", False),
    "mfds_15629.pdf": ("식약처", "디지털의료제품 법령 시행에 따른 업무 안내서 (2025.7.)", False),
    "mfds_15120.pdf": ("식약처", "의료기기의 사이버보안 적용방법 및 사례집 (안내서-0996-02, 2022.10.28.)", False),
    "mfds_14834.pdf": ("식약처", "의료기기 허가·심사 시 자주 묻는 사이버보안 질문집(FAQ) (2021.4.22.)", False),
    "mfds_15557.pdf": ("식약처", "의료기기의 사이버보안 허가·심사 가이드라인 (안내서-0995-04, 2024.11.27.) [구판]", True),
    "guide_2023_0995-03.pdf": ("식약처", "의료기기의 사이버보안 허가·심사 가이드라인 (안내서-0995-03, 2023.7.13.) [구판]", True),
    "cyber_premarket_guidance.pdf": ("FDA", "Cybersecurity in Medical Devices: QMS Considerations and Content of Premarket Submissions (2026.2.3.)", False),
    "denovo_esubmission_guidance.pdf": ("FDA", "Electronic Submission Template for De Novo Requests (2024.8.23.)", False),
    "estar_510k_guidance_2023.pdf": ("FDA", "Electronic Submission Template for 510(k) Submissions (2023.10.2.)", False),
    "cyber_tips.txt": ("FDA", "FDA eSTAR 사이버보안 작성 팁", False),
    "niv_cyber_text.txt": ("FDA", "FDA eSTAR (non-IVD) 사이버보안 항목", False),
    "ivd_cyber_text.txt": ("FDA", "FDA eSTAR (IVD) 사이버보안 항목", False),
    "webinar2023.txt": ("FDA", "FDA 사이버보안 가이던스 웨비나 (2023)", False),
}
SKIP = {"nIVD_eSTAR_v7_1.pdf", "cyber_tips_summary.txt"}  # 텍스트 추출 불가 양식 / 요약 중복

CHUNK_CHARS, OVERLAP = 700, 150
K1, B = 1.5, 0.75
_KEEP_TAGS = ("NNG", "NNP", "NR", "SL", "SN", "XR", "VV", "VA", "SH")
_kiwi = None


def _get_kiwi():
    global _kiwi
    if _kiwi is None:
        from kiwipiepy import Kiwi
        _kiwi = Kiwi()
    return _kiwi


def tokenize(text: str):
    toks = []
    for t in _get_kiwi().tokenize(text):
        if t.tag.startswith(_KEEP_TAGS) or t.tag in _KEEP_TAGS:
            form = t.form.lower()
            if len(form) > 1 or t.tag in ("NNG", "NNP", "SN"):
                toks.append(form)
    return toks


def _clean(text: str):
    text = text.replace("­", "").replace("\xa0", " ")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{2,}", "\n", text)
    return text.strip()


def _pages(path: Path):
    if path.suffix.lower() == ".pdf":
        doc = fitz.open(path)
        for i in range(doc.page_count):
            yield i + 1, _clean(doc[i].get_text())
    else:  # .txt — 쪽 개념이 없으므로 2,500자 단위를 한 '쪽'으로 본다
        text = _clean(path.read_text(encoding="utf-8", errors="replace"))
        for i in range(0, len(text), 2500):
            yield i // 2500 + 1, text[i:i + 2500]


def _chunks(text: str):
    if len(text) <= CHUNK_CHARS:
        yield text
        return
    start = 0
    while start < len(text):
        yield text[start:start + CHUNK_CHARS]
        start += CHUNK_CHARS - OVERLAP


def build_index(progress=None):
    files = [p for p in sorted(REGULATIONS_DIR.rglob("*"))
             if p.suffix.lower() in (".pdf", ".txt") and p.name not in SKIP]
    chunks = []
    for n, path in enumerate(files):
        org, title, superseded = DOCS.get(path.name, ("기타", path.stem, False))
        if superseded:
            continue
        for page, text in _pages(path):
            if len(text) < 60:
                continue
            for piece in _chunks(text):
                chunks.append({"org": org, "title": title, "file": path.name, "page": page, "text": piece})
        if progress:
            progress((n + 1) / len(files), path.name)

    postings, doc_len = defaultdict(list), []
    for i, ch in enumerate(chunks):
        tf = Counter(tokenize(ch["title"] + " " + ch["text"]))
        doc_len.append(sum(tf.values()))
        for term, c in tf.items():
            postings[term].append((i, c))
    index = {"chunks": chunks, "postings": dict(postings), "doc_len": doc_len,
             "avgdl": (sum(doc_len) / len(doc_len)) if doc_len else 0}
    INDEX_PATH.write_bytes(pickle.dumps(index))
    return index


_INDEX = None


def load_index():
    global _INDEX
    if _INDEX is None and INDEX_PATH.exists():
        _INDEX = pickle.loads(INDEX_PATH.read_bytes())
    return _INDEX


def reset_cache():
    global _INDEX
    _INDEX = None


def index_info():
    idx = load_index()
    if not idx:
        return None
    docs = Counter((c["org"], c["title"]) for c in idx["chunks"])
    return {"chunks": len(idx["chunks"]), "docs": [{"org": o, "title": t, "chunks": n}
                                                   for (o, t), n in sorted(docs.items())]}


def search(query: str, k: int = 5, org: str | None = None, extra_queries=(), per_doc: int = 2):
    """질문(과 영어 확장 질의)으로 상위 k개 근거 구간을 찾는다.
    한 문서가 결과를 독차지하지 않도록 문서당 최대 per_doc개로 제한한다."""
    idx = load_index()
    if not idx:
        return []
    n = len(idx["chunks"])
    scores = defaultdict(float)
    for q in (query, *extra_queries):
        for term in set(tokenize(q)):
            plist = idx["postings"].get(term)
            if not plist:
                continue
            idf = math.log(1 + (n - len(plist) + 0.5) / (len(plist) + 0.5))
            for i, tf in plist:
                dl = idx["doc_len"][i]
                scores[i] += idf * tf * (K1 + 1) / (tf + K1 * (1 - B + B * dl / idx["avgdl"]))
    ranked = sorted(scores.items(), key=lambda x: -x[1])
    out, per = [], Counter()
    for i, s in ranked:
        ch = idx["chunks"][i]
        if org and ch["org"] != org:
            continue
        if per[ch["file"]] >= per_doc:
            continue
        per[ch["file"]] += 1
        out.append({**ch, "score": round(s, 2)})
        if len(out) >= k:
            break
    return out
