# 메디가이드 (MediGuide)

**의료기기 보안 점검 · AI 조치 매뉴얼 검색 서비스**
2026 동북권 개발자 대상 오픈소스 아이디어 경진대회 · 8팀 무한루프 · 주제 06-02 (AI 기반 산업현장 작업 매뉴얼 검색 서비스)

의료기기 소프트웨어 소스코드를 올리면 오픈소스 정적분석으로 취약점을 찾고, 취약점마다 식약처·FDA 규제 문서에서
관련 요구사항과 조치 방법을 **근거(문서명·쪽)와 함께** 찾아 안내합니다. 근거가 없으면 지어내지 않고
"제공된 문서에서 근거를 찾을 수 없습니다"라고 답합니다.

## 주요 기능

| 화면 | 기능 |
|---|---|
| 대시보드 | 등록 장비·완료 점검·발견 취약점 지표, 심각도 분포, 고위험 기기 Top 5, 최근 점검 |
| 의료기기 관리 | 점검 대상 기기 등록·목록 |
| 점검 실행 | 소스 압축파일(.zip) 업로드 → OpenGrep/Semgrep 정적분석 → 100점 만점 점수·A~D 등급 |
| 점검 결과 | 취약점별 코드 위치·설명·의료기기 영향·조치 방법, **AI 조치 매뉴얼 찾기** |
| 매뉴얼 검색 | 규제 문서 근거 인용형 AI 질의응답 (식약처/FDA 범위 선택, 영문 문서 확장 검색) |
| 결과 리포트 | 점검 결과 + AI 조치 매뉴얼을 담은 PDF 리포트 |
| 시스템 설정 | 엔진·AI·색인 상태, 색인 재생성 |

## 구조

```
app/            Streamlit 화면 (main.py가 진입점, pages/ 에 화면별 파일)
core/           핵심 로직
  scanner.py    OpenGrep(없으면 Semgrep) 실행·결과 정리
  grading.py    점수·등급 산식 (화면·리포트에 공개)
  rag.py        규제 문서 쪽 단위 색인, Kiwi 형태소 + BM25 검색
  llm.py        근거 인용형 답변 (Ollama / Bedrock 전환), 근거 검증 후처리
  report.py     PDF 리포트 (fpdf2)
  db.py         SQLite 저장소 (별도 DB 서버 불필요)
scripts/        색인 생성, 시연 데이터, 시험 스크립트
data_local/     규칙·규제 원문·시연 펌웨어 (Git 제외 — 아래 참고)
storage/        실행 중 생성 파일 (Git 제외)
```

## 실행 방법 (로컬)

```bash
pip install -r requirements.txt
python scripts/build_index.py      # 규제 문서 검색 색인 (약 6초)
python scripts/seed_demo.py        # (선택) 시연용 기기·점검 데이터
streamlit run app/main.py
```

로컬 AI는 [Ollama](https://ollama.com)의 `exaone3.5:7.8b` 모델을 기본으로 사용합니다 (`ollama pull exaone3.5:7.8b`).

## AI 전환 (환경변수)

| 변수 | 값 |
|---|---|
| `MG_LLM` | `ollama`(기본, 로컬·온프레미스) · `bedrock`(대회 AWS) · `none`(검색 결과만) |
| `MG_OLLAMA_MODEL` | 기본 `exaone3.5:7.8b` |
| `MG_BEDROCK_MODEL` | 운영진이 안내한 Bedrock 모델 ID |
| `AWS_REGION` | 기본 `ap-northeast-2` |

같은 코드로 **클라우드형(Bedrock)** 과 **온프레미스 폐쇄망형(Ollama)** 을 모두 시연할 수 있습니다.

## EC2 배포 메모

- OpenGrep 설치 후 `opengrep` 명령이 있으면 Semgrep 대신 자동으로 사용합니다.
- 리포트 한글 글꼴: `sudo apt install fonts-nanum` (또는 `MG_FONT`로 글꼴 경로 지정)
- 외부 공개 실행: `streamlit run app/main.py --server.address 0.0.0.0 --server.port 8501`

## data_local/ 에 대해 (중요)

`data_local/` 에는 점검 규칙(OpenGrep 규칙·한글 문구표), 시연용 펌웨어(SecPump), 규제 원문 PDF가 들어갑니다.
이 중 점검 규칙과 시연 자료는 **소속 연구실 과제 산출물**이라 공개 저장소에 올리지 않습니다 (`.gitignore` 처리).
공개 여부는 지도교수 확인 후 결정하며, 대회 제출 시 '기술 활용 내역'에 활용 범위를 명시합니다.

## 활용 오픈소스

Streamlit · Plotly · PyMuPDF · Kiwi(kiwipiepy) · fpdf2 · OpenGrep / Semgrep · Ollama · EXAONE 3.5 · pandas · boto3

## 유의사항

본 서비스의 결과는 규칙 기반 정적분석과 공개 규제 문서 검색에 기반한 참고 자료입니다.
실제 인허가 제출 전에는 반드시 보안·인허가 전문가의 검토를 받아야 합니다.
