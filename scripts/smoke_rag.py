import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core import rag, llm
print("AI:", llm.provider_label(), "| 사용 가능:", llm.available())
qs = ["SBOM은 어떤 형식으로 제출해야 하나요?",
      "스택 버퍼 오버플로우 같은 메모리 취약점은 인허가 때 어떻게 조치해야 하나요?",
      "인슐린 펌프 배터리 교체 주기는 얼마인가요?"]
for q in qs:
    print("\n" + "="*70 + f"\n질문: {q}")
    hits = rag.search(q, k=5)
    for i, h in enumerate(hits, 1):
        print(f"  [{i}] ({h['org']}) {h['title'][:45]} p.{h['page']}  점수 {h['score']}")
    t = time.time()
    raw = "".join(llm.answer_stream(q, hits)); ans, nf = llm.finalize(raw, hits)
    print(f"--- 답변 ({time.time()-t:.1f}초) ---\n{ans}")
