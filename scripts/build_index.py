"""규제 문서 검색 색인을 만든다:  python scripts/build_index.py"""
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core import rag

t = time.time()
idx = rag.build_index(progress=lambda r, name: print(f"  {r*100:5.1f}%  {name}"))
info = rag.index_info()
print(f"완료: 구간 {info['chunks']}개, {time.time()-t:.1f}초")
for d in info["docs"]:
    print(f"  [{d['org']}] {d['title']}  ({d['chunks']}구간)")
