"""Bedrock 연결 확인:  MG_LLM=bedrock MG_BEDROCK_MODEL=<모델 ID> python scripts/check_bedrock.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core import config, llm  # noqa: E402

print("제공자:", llm.provider_label(), "| 리전:", config.BEDROCK_REGION)
if not llm.available():
    sys.exit("연결 불가: MG_BEDROCK_MODEL 값이나 AWS 자격증명(EC2 인스턴스 역할)을 확인하세요.")
ctx = [{"org": "FDA", "title": "시험", "page": 1, "text": "Manufacturers should provide a software bill of materials (SBOM)."}]
ans = "".join(llm.answer_stream("SBOM을 제출해야 하나?", ctx))
print("응답:", ans[:300])
print("정리:", llm.finalize(ans, ctx))
