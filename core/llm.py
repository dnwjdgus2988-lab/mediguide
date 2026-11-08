"""근거 인용형 답변 생성. MG_LLM 설정으로 Ollama(로컬·온프레미스) / Bedrock(AWS) / none 을 전환한다."""
import json
import urllib.request

from core import config

SYSTEM_PROMPT = """당신은 의료기기 인허가·사이버보안 규제 문서를 안내하는 도우미입니다.
반드시 지킬 규칙:
1. 아래 [근거]에 적힌 내용만 사용합니다. 근거에 없는 일반 상식, 추측, 권유를 덧붙이지 않습니다.
2. 문장마다 끝에 사용한 근거 번호를 [1] 형식으로 붙입니다.
3. [근거]에 질문의 답이 없으면 다른 말 없이 "제공된 문서에서 근거를 찾을 수 없습니다." 한 문장만 출력합니다.
4. 영어 근거는 한국어로 옮겨 설명합니다.
5. 약어·제품명·고유명사는 근거에 적힌 그대로 쓰고, 근거에 없는 뜻으로 풀어쓰지 않습니다.
6. 형식: 첫 줄에 핵심 답 1~2문장, 그 아래 "- "로 시작하는 목록으로 준비·조치 사항 3~5개. 제목, 굵은 글씨, "글머리표" 같은 표시어는 쓰지 않습니다."""

NOT_FOUND = "제공된 문서에서 근거를 찾을 수 없습니다."
# 모델이 '근거 없음'을 말하면서 다른 조언을 덧붙이는 경우를 잡아내기 위한 표현
_NOT_FOUND_SIGNS = ("근거를 찾을 수 없", "명시되어 있지 않", "포함되어 있지 않", "언급되어 있지 않",
                    "정보가 없", "확인되지 않", "구체적인 정보는 없")


def provider_label():
    p = config.LLM_PROVIDER
    if p == "ollama":
        return f"로컬 AI (Ollama · {config.OLLAMA_MODEL})"
    if p == "bedrock":
        return f"Amazon Bedrock ({config.BEDROCK_MODEL or '모델 미설정'})"
    return "AI 답변 끔 (검색 결과만 표시)"


_avail_cache = {"t": 0.0, "ok": False}


def available():
    p = config.LLM_PROVIDER
    if p == "ollama":
        import time
        # 모델이 답변을 만드는 중이면 상태 확인이 느릴 수 있어 넉넉히 기다리고, 성공 결과는 60초간 기억한다
        if _avail_cache["ok"] and time.time() - _avail_cache["t"] < 60:
            return True
        for _ in range(2):
            try:
                with urllib.request.urlopen(f"{config.OLLAMA_URL}/api/tags", timeout=10) as r:
                    names = [m["name"] for m in json.load(r).get("models", [])]
                ok = config.OLLAMA_MODEL in names
                _avail_cache.update(t=time.time(), ok=ok)
                return ok
            except OSError:
                continue
        return False
    if p == "bedrock":
        return bool(config.BEDROCK_MODEL)
    return False


def format_context(contexts):
    return "\n\n".join(
        f"[{i}] ({c['org']}) {c['title']}, {c['page']}쪽\n{c['text']}" for i, c in enumerate(contexts, 1))


def _messages(question, contexts):
    user = f"[근거]\n{format_context(contexts)}\n\n[질문]\n{question}"
    return SYSTEM_PROMPT, user


# ── Ollama ──────────────────────────────────────────────────
def _ollama_stream(system, user, temperature=0.1):
    body = json.dumps({
        "model": config.OLLAMA_MODEL, "stream": True,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        "options": {"temperature": temperature, "num_ctx": 8192},
        "keep_alive": "30m",  # 모델을 메모리에 유지해 두 번째 질문부터 빠르게
    }).encode()
    req = urllib.request.Request(f"{config.OLLAMA_URL}/api/chat", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as r:
        for line in r:
            if not line.strip():
                continue
            msg = json.loads(line)
            piece = msg.get("message", {}).get("content", "")
            if piece:
                yield piece
            if msg.get("done"):
                break


# ── Bedrock ─────────────────────────────────────────────────
def _bedrock_stream(system, user, temperature=0.1):
    import boto3
    client = boto3.client("bedrock-runtime", region_name=config.BEDROCK_REGION)
    resp = client.converse_stream(
        modelId=config.BEDROCK_MODEL,
        system=[{"text": system}],
        messages=[{"role": "user", "content": [{"text": user}]}],
        inferenceConfig={"temperature": temperature, "maxTokens": 1500},
    )
    for event in resp["stream"]:
        delta = event.get("contentBlockDelta", {}).get("delta", {})
        if "text" in delta:
            yield delta["text"]


def _stream(system, user):
    if config.LLM_PROVIDER == "ollama":
        return _ollama_stream(system, user)
    if config.LLM_PROVIDER == "bedrock":
        return _bedrock_stream(system, user)
    raise RuntimeError("AI 답변 생성이 꺼져 있습니다 (MG_LLM=none).")


def answer_stream(question, contexts):
    """근거가 하나도 없으면 AI를 부르지 않고 바로 '찾을 수 없음'을 돌려준다."""
    if not contexts:
        yield NOT_FOUND
        return
    system, user = _messages(question, contexts)
    yield from _stream(system, user)


def _norm(s: str):
    import re
    return re.sub(r"\s+", "", s).lower()


def finalize(answer: str, contexts):
    """스트리밍이 끝난 답변 후처리(근거 검증 단계).
    1) 첫머리에서 '근거 없음'을 말했다면 덧붙인 조언을 버리고 표준 문구만 남긴다.
    2) 정상 답변 끝에 잘못 붙은 '근거 없음' 문장을 지운다.
    3) [2(사)] 같은 변형 근거 번호를 [2]로 정리하고, 없는 번호는 지운다.
    4) 괄호 속 영문 풀이가 근거 원문에 없으면 지운다(약어를 지어내 풀어쓴 경우).
    5) 근거 번호가 하나도 남지 않으면 근거 기반 답변으로 인정하지 않는다.
    반환: (최종 답변, 근거없음 여부)"""
    import re
    n = len(contexts)
    source = _norm(" ".join(c["text"] for c in contexts))
    text = answer.strip()
    if any(s in text[:80] for s in _NOT_FOUND_SIGNS):
        return NOT_FOUND, True
    text = re.sub(r"\s*제공된 문서에서 근거를 찾을 수 없습니다\.?\s*(\[[^\]]*\]\s*)*$", "", text)
    text = re.sub(r"\[(\d+)[^\]\d][^\]]*\]", r"[\1]", text)  # [2(사)] → [2]
    text = re.sub(r"\[(\d+)\]", lambda m: m.group(0) if 1 <= int(m.group(1)) <= n else "", text)
    text = re.sub(r"(\[\d+\])(\.?)\s*\1", r"\1\2", text)  # [2].[2] → [2].

    def _check_paren(m):
        inner = m.group(1)
        if len(re.findall(r"[A-Za-z]", inner)) >= 4 and _norm(inner) not in source:
            return ""
        return m.group(0)
    text = re.sub(r"\s?\(([^()]{3,80})\)", _check_paren, text)
    text = text.replace("**", "").strip()
    if not re.search(r"\[\d+\]", text):
        return NOT_FOUND, True
    return text, False


def warm_up():
    """앱 시작 시 로컬 모델을 미리 올려 첫 질문 대기를 줄인다."""
    if config.LLM_PROVIDER == "ollama" and available():
        try:
            "".join(_ollama_stream("짧게 답하세요.", "안녕"))
        except Exception:
            pass


def expand_query_en(question):
    """FDA(영문) 문서 검색용 영어 키워드. 실패하면 빈 문자열."""
    if not available():
        return ""
    system = "Translate the user's Korean question into 5-10 English search keywords for FDA medical device guidance. Output keywords only, space-separated."
    try:
        return "".join(_stream(system, question)).strip()[:300]
    except Exception:
        return ""
