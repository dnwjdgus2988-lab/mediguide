# 메디가이드 (MediGuide)

**의료기기 보안 점검 · AI 조치 매뉴얼 검색 서비스**
2026 동북권 개발자 대상 오픈소스 아이디어 경진대회 · 8팀 무한루프 · 주제 06-02 (AI 기반 산업현장 작업 매뉴얼 검색 서비스)

의료기기 소프트웨어 소스코드를 올리면 오픈소스 정적분석(OpenGrep)으로 취약점을 찾고, 보안 체크리스트(20문항)·증빙 13종·
표준화 요구항목으로 인허가 제출 준비도를 평가해 **보안성 검증 리포트**와 **관할별 결과보고서(식약처·FDA·EU)** 를 만듭니다.
취약점마다 식약처·FDA 규제 문서에서 조치 방법을 **근거(문서명·쪽)와 함께** 찾아 주는 **AI 조치 매뉴얼**이 붙어 있으며,
근거가 없으면 지어내지 않고 「제공된 문서에서 근거를 찾을 수 없습니다」라고 답합니다.

- **서비스 주소:** http://52.11.149.157 (AWS EC2 us-west-2 · Amazon Bedrock Claude Haiku 4.5)
- **왜 이 주제인가:** 의료기기 도시 원주의 중소 제조사가 수출(FDA §524B 등) 과정에서 마주하는 사이버보안 인허가 문턱을 낮추기 위해

## 시연 순서 (약 3분)

1. **등록** — 의료기기 관리 ▸ 자산 등록 ▸ 사이버 기기 3문항 → §524B 사이버 기기 자동 판정
2. **분석** — 증빙 자료 탭에 펌웨어 소스 zip 업로드 ▸ 정적분석 시작 → 8단계 자동 진행(운영 서버 약 10초) → 검출 · AI 조치 매뉴얼
3. **다운로드** — 분석이 끝나면 리포트 자동 발행 ▸ 제출 패키지(zip): 리포트 HTML·PDF · 관할별 양식 5종 · 취약점 CSV · SBOM
4. **결과 확인** — 대시보드 기기 구조 분석(검출을 탑재 부품에 표시 · 위험 경로) · 기기별 충족률 · 최종 등급 · FDA 적합성

시연 데이터: `data_local/samples/secpump-vuln`(취약판) · `secpump-vanilla`(보완판)을 zip으로 묶어 업로드

## 화면 구성

| 메뉴 | 기능 |
|---|---|
| 대시보드 | 평균 문서 충족률 · FDA 적합성 분포 · 취약점 · 처분 진행, **기기 구조 분석**(인슐린펌프 3D 분해도 · 설계도 개념도 위에 검출 위치와 위험 경로 표시, 5초 자동 넘김), 기기별 최종 등급(상한 반영) · 다음 할 일, 최근 활동 |
| 의료기기 관리 | FDA 적합성(적합·조건부 적합·부적합·해당 없음·판정 불가)별 목록, 자산 등록 |
| └ 기기 상세 | **기본 정보**(장비 정보, 제출 정보·§524B(c) 사이버 기기 판정, 평가 회차·리포트, 변경 이력) · **스캔 결과**(회차 비교) · **증빙 자료**(소스 업로드 → 8단계 분석 진행 표시, 증빙 D01~D13) · **체크리스트**(SPDF 4개 영역 20문항, 문서 충족률·등급 상한) · **표준화**(요구항목 12개, 4축 지표, FDA·MFDS·MDR·IMDRF 판정) · **SBOM**(CycloneDX 1.5, OSV.dev 취약점, D08 증빙 등록) · 제출 패키지(zip) |
| 보안 평가 ▸ 정적분석 결과 | 스캔 목록, 스캔 상세(검출 목록 → 코드·설명·의료기기 영향·조치, **AI 조치 매뉴얼**, 검출 처분 기록) |
| 평가 관리 | 평가 회차 목록, 작성중 → 검토대기 → 승인완료/반려 흐름, 승인 시 리포트 자동 발행 |
| 리포트 | 9절 보안성 검증 리포트(화면·인쇄·PDF), 재발행·폐기, **관할별 결과보고서** 식약처 시험성적서 / FDA Test Report / EU Test Report |
| AI 매뉴얼 검색 | 규제 문서 근거 인용형 질의응답 (식약처/FDA 범위, 영문 확장 검색) |
| 관리자 | 사용자 관리(관리자·검증자·열람자), 감사 로그(CSV), 정책값(배점·적용조건·등급 구간·상한·CVSS 구간), 시스템 설정 |

## 판정 산식 (화면·리포트에 공개)

- **문서 충족률** = 충족 배점 / 적용 배점 × 100. 「예」는 연계 증빙이 없으면 배점의 50%만 인정, 「비적용」·적용조건 밖 문항은 분모에서 제외
- **등급** A ≥ 90 · B ≥ 80 · C ≥ 70 · D. Critical·High 취약점이 남아 있으면 **등급 상한 D**
- **FDA 제출 적합성** — §524B 법정 요건(SBOM Q16·D08, 취약점 모니터링 Q17·D09, 보안 업데이트 절차 Q18·D13) 중 하나라도 미충족이면 부적합, 충족 + 등급 A·B면 적합, 그 외 조건부 적합
- 모든 값은 관리자 ▸ 정책값에서 바꿀 수 있고, 발행된 리포트는 발행 당시 값을 유지합니다.

## 구조

```
web/              FastAPI 웹 서버 (main.py), 화면 템플릿(templates/), 스타일·스크립트(static/)
core/
  service.py      업무 로직 (기기·증빙·스캔·평가·리포트·대시보드)
  scanner.py      OpenGrep(없으면 Semgrep) 실행, 자체 룰 + CWE Top 25 공개 룰팩, 제외 경로·언어 분포·해시 기록
  sbom.py         SBOM 생성(npm·PyPI·Go·Rust·Maven + 펌웨어 내장 라이브러리), CycloneDX 1.5, OSV.dev 조회
  checklist.py    체크리스트 20문항·증빙 13종·충족률·등급·FDA 적합성
  standards.py    표준화 요구항목 12개 자동 판정, 4축 지표, 관할별 판정
  forms.py        관할별 결과보고서(식약처·FDA·EU) 데이터 구성
  policy.py       정책값 저장소
  rag.py · llm.py 규제 문서 검색(Kiwi + BM25) · 근거 인용형 답변(Ollama / Bedrock)
  pdf.py          HTML → PDF (헤드리스 Chrome/Chromium)
  db.py           SQLite (별도 DB 서버 불필요)
scripts/          색인 생성, 시연 데이터, 시험 스크립트
data_local/       규칙·규제 원문·시연 펌웨어 (Git 제외 — 아래 참고)
storage/          실행 중 생성 파일 (Git 제외)
```

## 실행 방법 (로컬)

```bash
pip install -r requirements.txt
python scripts/build_index.py              # 규제 문서 검색 색인 (약 6초)
python -X utf8 scripts/seed_demo.py --reset  # (선택) 시연 데이터: SecPump 취약판·보완판
python -X utf8 -m uvicorn web.main:app --port 8501
```

브라우저에서 `http://localhost:8501` 접속. 초기 계정은 `scripts/seed_demo.py` 상단 주석 참고
(배포 시 `MG_ADMIN_PASSWORD`, `MG_VERIFIER_PASSWORD`, `MG_SECRET` 환경변수로 반드시 바꿀 것).

로컬 AI는 [Ollama](https://ollama.com)의 `exaone3.5:7.8b` 모델을 기본으로 사용합니다 (`ollama pull exaone3.5:7.8b`).

## 환경변수

| 변수 | 값 |
|---|---|
| `MG_LLM` | `ollama`(기본, 로컬·온프레미스) · `bedrock`(대회 AWS) · `none`(검색 결과만) |
| `MG_OLLAMA_MODEL` | 기본 `exaone3.5:7.8b` |
| `MG_BEDROCK_MODEL` | 운영진이 안내한 Bedrock 모델 ID |
| `AWS_REGION` | 기본 `ap-northeast-2` |
| `MG_SECRET` | 세션 서명 키 (배포 시 필수 변경) |
| `MG_CHROME` | PDF 변환용 Chrome/Chromium 경로 (자동 탐색 실패 시) |

같은 코드로 **클라우드형(Bedrock)** 과 **온프레미스 폐쇄망형(Ollama)** 을 모두 시연할 수 있습니다.

## EC2 배포 메모

- OpenGrep 설치 후 `opengrep` 명령이 있으면 Semgrep 대신 자동으로 사용합니다.
- PDF: `sudo apt install chromium-browser fonts-nanum` (없으면 브라우저 인쇄 화면으로 PDF 저장 안내)
- 외부 공개 실행: `uvicorn web.main:app --host 0.0.0.0 --port 8501`

## data_local/ 구성

| 폴더 | 내용 |
|---|---|
| `rules/` | 의료기기 펌웨어 검사 룰 8종(OpenGrep 형식)과 한글 문구표 |
| `samples/` | 시연용 소스: SecPump 취약판·보완판, 결함 시드 5종, OpenAPS oref0 (공개 펌웨어 묶음 `realfw/`는 용량 때문에 Git 제외) |
| `regulations/` | 식약처·FDA 공개 규제 문서 (AI 매뉴얼 검색 대상) |

## 기술 활용 내역

| 구분 | 내용 |
|---|---|
| 오픈소스 | FastAPI · Uvicorn · Jinja2 · OpenGrep / Semgrep · CWE Top 25 룰팩 · CycloneDX · PyMuPDF · Kiwi(kiwipiepy) · Ollama · EXAONE 3.5 · boto3 · Chromium(PDF) · SQLite · nginx |
| 생성형 AI | 서비스: Amazon Bedrock **Claude Haiku 4.5**(근거 인용 답변 · 영문 검색어 확장) / Ollama **EXAONE 3.5**(폐쇄망) · 개발 보조: Anthropic **Claude Code** · 대시보드 개념도 2장: Google **Gemini** |
| 외부 API | Amazon Bedrock Runtime(ConverseStream) — 소스코드 미전송, 질문 + 공개 규제 문서 근거만 전송 · OSV.dev(알려진 취약점 조회) |
| 기존 코드 | 의료기기 펌웨어 룰셋 8종(`data_local/rules`)은 팀원 선행 연구 MediHub v2.0(상지대학교 산학협력단, 2026-08)에서 재사용. 웹 서비스 · 판정 · AI · 리포트 코드는 대회 기간(2026-11-08~) 작성 |
| 데이터 | 식약처 · FDA 공개 규제 문서 13종, SecPump(공개 연구용 펌웨어), OpenAPS oref0(MIT), 공개 펌웨어 6종(각 저장소 라이선스) |

## 유의사항

본 서비스의 결과는 규칙 기반 정적분석과 공개 규제 문서 검색에 기반한 참고 자료이며 규제 판정이 아닙니다.
실제 인허가 제출 전에는 반드시 보안·인허가 전문가의 검토를 받아야 합니다.
