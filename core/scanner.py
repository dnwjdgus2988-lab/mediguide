"""정적분석 엔진 래퍼. OpenGrep을 우선 사용하고, 없으면 같은 규칙 형식의 Semgrep으로 대체한다."""
import json
import os
import shutil
import subprocess
import zipfile
from pathlib import Path

from core.config import RULES_DIR, RULE_MESSAGES

CODE_EXT = {".c", ".h", ".cpp", ".hpp", ".cc", ".py", ".js", ".ts", ".java", ".kt", ".go", ".rs", ".cs"}
# 규칙 한글표에 없을 때만 쓰는 대체 매핑 (규칙표의 severity가 항상 우선)
FALLBACK_SEVERITY = {"ERROR": "High", "WARNING": "Medium", "INFO": "Low"}


def find_engine():
    for name in ("opengrep", "semgrep"):
        path = shutil.which(name)
        if path:
            return name, path
    return None, None


def rule_files():
    return sorted(RULES_DIR.glob("*.yaml")) + sorted(RULES_DIR.glob("*.yml"))


def load_rule_messages():
    if RULE_MESSAGES.exists():
        return json.loads(RULE_MESSAGES.read_text(encoding="utf-8")).get("rules", {})
    return {}


def safe_extract_zip(zip_path: Path, dest: Path):
    """압축 해제 시 경로 탈출(zip slip)을 막는다."""
    dest = dest.resolve()
    with zipfile.ZipFile(zip_path) as z:
        for m in z.infolist():
            target = (dest / m.filename).resolve()
            if not str(target).startswith(str(dest)):
                raise ValueError(f"허용되지 않는 경로가 포함된 압축 파일입니다: {m.filename}")
        z.extractall(dest)
    return dest


def count_code_files(target: Path):
    return sum(1 for p in target.rglob("*") if p.is_file() and p.suffix.lower() in CODE_EXT)


def _read_lines(path: Path, start: int, end: int):
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        return "\n".join(lines[max(0, start - 1):end])
    except OSError:
        return ""


def scan(target: Path):
    """대상 폴더를 점검해 (취약점 목록, 엔진 이름, 점검 파일 수)를 돌려준다."""
    engine, path = find_engine()
    if not engine:
        raise RuntimeError("정적분석 엔진(OpenGrep 또는 Semgrep)이 설치되어 있지 않습니다.")
    rules = rule_files()
    if not rules:
        raise RuntimeError(f"점검 규칙 파일이 없습니다: {RULES_DIR}")

    cmd = [path, "scan", "--json", "--quiet"]
    for r in rules:
        cmd += ["--config", str(r)]
    if engine == "semgrep":
        cmd += ["--metrics=off"]
    cmd.append(str(target))

    env = dict(os.environ, SEMGREP_SEND_METRICS="off", PYTHONUTF8="1")
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", env=env, timeout=900)
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise RuntimeError(f"점검 엔진 실행 실패: {proc.stderr[-500:]}")

    messages = load_rule_messages()
    findings, seen = [], set()
    for r in data.get("results", []):
        rule_id = r["check_id"].split(".")[-1]
        file_abs = Path(r["path"])
        try:
            rel = str(file_abs.resolve().relative_to(target.resolve())).replace("\\", "/")
        except ValueError:
            rel = r["path"]
        line, end_line = r["start"]["line"], r["end"]["line"]
        key = (rule_id, rel, line)
        if key in seen:  # 같은 규칙·파일·줄 중복 제거
            continue
        seen.add(key)

        meta = messages.get(rule_id, {})
        md = r["extra"].get("metadata", {})
        cwe = meta.get("cwe") or (md.get("cwe")[0] if isinstance(md.get("cwe"), list) else md.get("cwe", ""))
        if cwe and ":" in str(cwe):
            cwe = str(cwe).split(":")[0].strip()
        findings.append({
            "rule_id": rule_id,
            "cwe": cwe or "",
            "severity": meta.get("severity") or FALLBACK_SEVERITY.get(r["extra"].get("severity"), "Low"),
            "title": meta.get("name_ko") or rule_id,
            "file": rel,
            "line": line,
            "end_line": end_line,
            "code": _read_lines(file_abs, line, end_line),
            "message": r["extra"].get("message", ""),
        })
    return findings, engine, count_code_files(target)


def rule_detail(rule_id):
    """취약점 상세 화면·리포트용 한글 설명 (규칙표에 없으면 빈 dict)."""
    return load_rule_messages().get(rule_id, {})
