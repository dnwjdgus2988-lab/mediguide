"""시연용 데이터 만들기:  python -X utf8 scripts/seed_demo.py [--reset]

SecPump 무선 인슐린펌프 펌웨어(공개 연구용 샘플)의 취약판·보완판을 등록하고
정적분석 → 체크리스트 → 검토 요청 → 승인(리포트 발행)까지 실행한다.
초기 계정: admin / medi1234!  ·  verifier / verify1234!  (MG_ADMIN_PASSWORD 등으로 변경)
"""
import os
import shutil
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core import config, db, policy, service  # noqa: E402

if "--reset" in sys.argv and config.DB_PATH.exists():
    for p in (config.DB_PATH, Path(str(config.DB_PATH) + "-wal"), Path(str(config.DB_PATH) + "-shm")):
        if p.exists():
            p.unlink()
    shutil.rmtree(config.UPLOADS, ignore_errors=True)
    config.UPLOADS.mkdir(parents=True, exist_ok=True)

db.init_db()
policy.seed()
if not db.one("SELECT id FROM users LIMIT 1"):
    service.create_user("admin", os.getenv("MG_ADMIN_PASSWORD", "medi1234!"), "관리자", "admin@mediguide.local", "8팀 무한루프")
    service.create_user("verifier", os.getenv("MG_VERIFIER_PASSWORD", "verify1234!"), "검증자", "verifier@mediguide.local", "8팀 무한루프")
if db.one("SELECT id FROM devices LIMIT 1"):
    print("이미 데이터가 있습니다. 처음부터 다시 하려면 --reset 을 붙여 실행하세요.")
    sys.exit(0)


def zip_dir(folder: Path, name: str):
    out = config.UPLOADS / "sources" / name
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(folder.rglob("*")):
            if p.is_file():
                z.write(p, p.relative_to(folder))
    return out


def device(name, model, version, desc, name_en=""):
    _id, code = service.add_device({"name": name, "name_en": name_en, "model": model, "maker": "오픈소스 검증용 샘플",
                                    "maker_en": "Open-source research sample (github.com/r3glisss/SecPump)" if name_en else "", "device_class": "Class II",
                                    "sw_version": version, "fw_version": version, "description": desc,
                                    "target_market": "미국 FDA", "submission_path": "510(k)", "is_modification": 0,
                                    "has_software": 1, "internet": 1, "vuln_tech": 1}, "admin")
    db.audit("admin", "기기 등록", f"{name} ({code})", "127.0.0.1")
    return service.get_device_by_code(code)


def scan(dev, folder, zipname, version):
    arc = zip_dir(config.SAMPLES_DIR / folder, zipname)
    db.audit("admin", "증빙 자료 업로드", f"{dev['name']} / {zipname}", "127.0.0.1")
    code = service.start_scan(dev, arc, zipname, version, "admin", background=False)
    s = service.get_scan(code)
    print(f"  {code}: {s['status']} · 파일 {s['files_scanned']} · 검출 {s['n_critical']}/{s['n_high']}/{s['n_medium']}/{s['n_low']} {s['error'] or ''}")
    return s


# ── 1) 취약판: 증빙 없이 「예」 14문항 → 문서 충족률 35.5, 법정 요건 미충족 → 부적합 ──
d1 = device("SecPump 무선 인슐린펌프", "SecPump-Vuln", "1.0.0",
            "STM32 + BLE 인슐린 주입 펌프 펌웨어 (공개 연구용 샘플, 의도적 취약 빌드)", "SecPump wireless insulin pump")
no = {"Q3", "Q6", "Q9", "Q12", "Q15", "Q18"}
ans1 = {f"Q{i}": ("아니오" if f"Q{i}" in no else "예") for i in range(1, 21)}
acode, _ = service.save_checklist(d1, ans1, "admin")
s1 = scan(d1, "secpump-vuln", "SecPump-Vuln_취약버전.zip", "1.0.0")
service.request_review(service.get_assessment(acode), "admin")
rpt = service.approve(service.get_assessment(acode), "verifier", "시연용 샘플 승인")
print(f"  {acode} 승인 → {rpt}")

# 검출 처분(코드 검토) 기록 — 관할별 결과보고서 판정에 반영
TRIAGE = {
    ("app_x-cube-ble1.c", 100): ("오탐", "None", "6바이트 배열 bdaddr와 sizeof(SERVER_BDADDR) 길이 복사의 짝으로, 복사 길이가 대상 크기와 같은 컴파일 시 상수라 넘침이 불가능함. 벤더 생성 코드(ST X-CUBE-BLE1).", "코드 수정 불필요. 룰에 sizeof·상수 길이 예외 추가."),
    ("PumpService.c", 401): ("확인된 결함", "High", "VulnBuffer[4]에 BLE 쓰기로 쌓인 112바이트가 경계 없는 복사(MaliciousMemCpy)로 들어가 스택이 넘침. 해당 특성은 무인증(ATTR_PERMISSION_NONE)이라 인접 공격자가 도달 가능.", "취약 특성·처리부 제거 또는 복사 길이를 sizeof(VulnBuffer) 이하로 제한, 인증·암호화된 쓰기만 허용."),
    ("InsulinController.c", 114): ("확인된 결함", "Medium", "UART 혈당 문자열을 atof로 변환해 범위·NaN 검사 없이 PID 계산에 사용. 출력만 0~100으로 제한되어 이상값은 최대 출력, 변환 실패는 0 mg/dL로 처리됨.", "strtof·endptr·isfinite 검사, 생리적 범위 밖이면 센서 오류로 거부·경보·투여 보류."),
    ("InsulinController.c", 162): ("약점", "Low", "atof 결과를 로그 출력에만 사용하고 투여량 결정에는 쓰지 않음. 안전 영향 낮음.", "114행과 같은 검증 함수로 통일(우선순위 낮음)."),
    ("PumpService.c", 374): ("약점", "Low", "uint8_t로 잘린 뒤 0/1 화이트리스트를 거치나 비숫자 입력이 0이 되어 자동 모드로 전환됨. 정상값 「0」 쓰기와 효과가 같아 견고성 문제.", "길이 1이고 「0」 또는 「1」일 때만 수용."),
    ("PumpService.c", 391): ("확인된 결함", "High", "무인증 BLE Bolus 특성 값을 atof로 변환해 검사 없이 수동 모드 주입량으로 사용. 음수·초대량·NaN 볼루스가 그대로 나가 환자 위해로 직결.", "범위 밖·비정상 볼루스는 거부·경보, Bolus 특성은 인증·암호화된 쓰기만 허용."),
}
for f in service.findings(s1["id"]):
    key = (Path(f["file"]).name, f["line"])
    if key in TRIAGE:
        dsp, sev, why, act = TRIAGE[key]
        service.triage(f["id"], dsp, sev, why, act, "verifier")
db.audit("verifier", "검출 처분 기록", f"{s1['code']} 6건", "127.0.0.1")

# ── 2) 보완판: 증빙 제출 + 「예」 → 충족률 높음, 법정 요건 충족(High 1건으로 등급 상한 D → 조건부 적합) ──
d2 = device("SecPump 무선 인슐린펌프 (보완판)", "SecPump-Vanilla", "1.0.1",
            "취약 BLE 특성을 제거한 정상 빌드 (공개 연구용 샘플)", "SecPump wireless insulin pump (revised build)")
for code, name, level, qs in [e for e in __import__("core.checklist", fromlist=["EVIDENCE"]).EVIDENCE]:
    if code in ("D03", "D11", "D12"):
        continue
    body = (f"[시연용 샘플 문서 — 실제 증빙 아님]\n{code} {name}\n기기: {d2['name']} ({d2['code']})\n"
            "메디가이드 시연을 위해 만든 자리표시 파일입니다.\n").encode("utf-8")
    service.save_evidence(d2["id"], code, f"SAMPLE_{code}.txt", body, "admin")
ans2 = {f"Q{i}": "예" for i in range(1, 21)}
ans2.update({"Q5": "아니오", "Q20": "아니오"})
acode2, _ = service.save_checklist(d2, ans2, "admin")
s2 = scan(d2, "secpump-vanilla", "SecPump-Vanilla_보완버전.zip", "1.0.1")
service.request_review(service.get_assessment(acode2), "admin")
rpt2 = service.approve(service.get_assessment(acode2), "verifier", "증빙 확인 — 시연용 샘플")
print(f"  {acode2} 승인 → {rpt2}")

# ── 3) 검증용 데이터셋: 정적분석만 (체크리스트 미응답 → 시스템 평가로 리포트 발행) ──
extra = []
for folder, name, model, maker, desc in [
    ("seeds-5", "[검증] 결함 시드 5종 (인슐린펌프 관용구)", "SEED-5", "상지대 검증용 시드",
     "CWE-120/134/327/338/798 결함을 인슐린펌프 코드 관용구로 심은 시험 파일 5종"),
    ("oref0", "[검증] OpenAPS oref0 인공췌장 SW", "oref0-0.7.1", "OpenAPS (MIT License)",
     "인공췌장 알고리즘 오픈소스(JavaScript). 정적분석보다 SBOM 기반 구성요소 취약점이 주요 시연 대상"),
    ("realfw", "[검증] 공개 펌웨어 6종 (STM32·FreeRTOS·libopencm3)", "REALFW-6", "공개 소스 (각 저장소 라이선스)",
     "STM32F4 BSP·HAL, USB 미들웨어, FreeRTOS 커널, libopencm3 예제 등 공개 임베디드 펌웨어"),
]:
    if not (config.SAMPLES_DIR / folder).exists():
        print(f"  {folder} 폴더가 없어 건너뜁니다")
        continue
    _id, code = service.add_device({"name": name, "model": model, "maker": maker, "device_class": "Class II",
                                    "sw_version": "1.0.0", "fw_version": "1.0.0", "description": desc,
                                    "target_market": "미국 FDA", "submission_path": "510(k)",
                                    "has_software": 1, "internet": 1, "vuln_tech": 1}, "admin")
    db.audit("admin", "기기 등록", f"{name} ({code})", "127.0.0.1")
    dv = service.get_device_by_code(code)
    scan(dv, folder, f"검증_{model}_src.zip", "1.0.0")
    extra.append(code)

# ── 4) 등록만 한 기기 (판정 불가) ──
d3 = device("스마트 혈당측정기 게이트웨이", "GlucoLink-GW", "0.9.0", "블루투스 혈당측정기 데이터를 병원 서버로 전송하는 게이트웨이 (등록 예시)")
print("완료:", [d1["code"], d2["code"], *extra, d3["code"]])
