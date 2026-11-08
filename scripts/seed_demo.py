"""시연용 데이터 만들기:  python scripts/seed_demo.py
SecPump 무선 인슐린펌프 펌웨어의 취약판·정상판을 등록하고 점검까지 실행한다."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core import db, grading, scanner  # noqa: E402
from core.config import SAMPLES_DIR  # noqa: E402

db.init_db()
if db.list_devices():
    print("이미 데이터가 있습니다. 처음부터 다시 하려면 storage/mediguide.db 를 지우고 실행하세요.")
    sys.exit(0)

dev_id = None
code = db.add_device("SecPump 무선 인슐린펌프", "SecPump", "오픈소스 연구용 펌웨어",
                     "주입기기(인슐린·수액 펌프)", "STM32 + BLE 통신 인슐린 주입 펌프 펌웨어 (공개 연구용)")
dev_id = next(d["id"] for d in db.list_devices() if d["code"] == code)

for folder, version, label in [("secpump-vanilla", "1.0.0", "정상 버전"), ("secpump-vuln", "1.0.1", "취약 버전")]:
    target = SAMPLES_DIR / folder
    scan_id = db.create_scan(dev_id, version, f"SecPump 펌웨어 — {label}")
    findings, eng, nfiles = scanner.scan(target)
    score, grade = grading.score_findings(findings)
    db.finish_scan(scan_id, findings, score, grade, eng, nfiles)
    print(f"{label}: 파일 {nfiles}개, 취약점 {len(findings)}건, {score}점 {grade}등급")
print("완료")
