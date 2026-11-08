"""정적분석 엔진 래퍼. OpenGrep을 우선 사용하고, 없으면 같은 규칙 형식의 Semgrep으로 대체한다."""
import hashlib
import json
import os
import shutil
import subprocess
import time
import zipfile
from pathlib import Path

from core.config import RULES_DIR, RULE_MESSAGES

LANG_EXT = {".c": "C", ".h": "C", ".cpp": "C++", ".hpp": "C++", ".cc": "C++", ".py": "Python", ".java": "Java",
            ".cs": "C#", ".js": "JavaScript", ".ts": "TypeScript", ".go": "Go", ".rs": "Rust", ".kt": "Kotlin"}
# 규칙 한글표에 없을 때만 쓰는 대체 매핑 (규칙표의 severity가 항상 우선, SARIF level은 쓰지 않음)
FALLBACK_SEVERITY = {"ERROR": "High", "WARNING": "Medium", "INFO": "Low"}
DEFAULT_EXCLUDES = ("venv,site-packages,node_modules,.git,build,dist,out,third_party,external,vendor,deps,"
                    "Middlewares,Drivers,CMSIS,__pycache__")


def find_engine():
    for name in ("opengrep", "semgrep"):
        path = shutil.which(name)
        if path:
            return name, path
    return None, None


_ver_cache = {}


def engine_version():
    name, path = find_engine()
    if not name:
        return "미설치"
    if name not in _ver_cache:
        try:
            out = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=60).stdout.strip()
            _ver_cache[name] = f"{'Opengrep' if name == 'opengrep' else 'Semgrep'} {out.splitlines()[-1] if out else ''}".strip()
        except (OSError, subprocess.SubprocessError):
            _ver_cache[name] = name
    return _ver_cache[name]


def rule_files():
    return sorted(RULES_DIR.glob("*.yaml")) + sorted(RULES_DIR.glob("*.yml"))


def ruleset_sha256():
    h = hashlib.sha256()
    for r in rule_files():
        h.update(r.read_bytes())
    return h.hexdigest()


def load_rule_messages():
    if RULE_MESSAGES.exists():
        return json.loads(RULE_MESSAGES.read_text(encoding="utf-8")).get("rules", {})
    return {}


def rule_detail(rule_id):
    """취약점 상세 화면·리포트용 한글 설명 (규칙표에 없으면 빈 dict)."""
    return load_rule_messages().get(rule_id, {})


def sha256_file(p: Path):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_extract(archive: Path, dest: Path):
    """.zip / .tar.gz / .tgz 해제. 경로 탈출(zip slip)을 막는다."""
    dest = dest.resolve()
    dest.mkdir(parents=True, exist_ok=True)
    name = archive.name.lower()
    if name.endswith(".zip"):
        with zipfile.ZipFile(archive) as z:
            for m in z.infolist():
                if not str((dest / m.filename).resolve()).startswith(str(dest)):
                    raise ValueError(f"허용되지 않는 경로가 포함된 압축 파일입니다: {m.filename}")
            z.extractall(dest)
    elif name.endswith((".tar.gz", ".tgz")):
        import tarfile
        with tarfile.open(archive) as t:
            for m in t.getmembers():
                if not str((dest / m.name).resolve()).startswith(str(dest)) or m.issym() or m.islnk():
                    raise ValueError(f"허용되지 않는 경로가 포함된 압축 파일입니다: {m.name}")
            t.extractall(dest)
    else:
        raise ValueError("지원 형식은 .zip · .tar.gz · .tgz 입니다.")
    return dest


def _excluded(rel: str, excludes):
    parts = rel.replace("\\", "/").split("/")
    return any(p in excludes for p in parts[:-1])


def inventory(target: Path, excludes):
    """분석 대상 코드 파일 수·줄 수·언어 분포 (제외 경로는 따로 센다)."""
    files = lines = excluded = 0
    langs = {}
    for p in target.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in LANG_EXT:
            continue
        rel = str(p.relative_to(target))
        if _excluded(rel, excludes):
            excluded += 1
            continue
        files += 1
        lang = LANG_EXT[p.suffix.lower()]
        langs[lang] = langs.get(lang, 0) + 1
        try:
            lines += sum(1 for _ in open(p, encoding="utf-8", errors="replace"))
        except OSError:
            pass
    return files, lines, langs, excluded


def _snippet(path: Path, line: int, end_line: int):
    """보고 줄부터 아래로 최대 14줄 (상세 팝업의 코드 보기)."""
    try:
        all_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return "", "", line
    code = "\n".join(all_lines[max(0, line - 1):end_line])
    start = line
    snip = "\n".join(all_lines[start - 1:start + 13])
    return code, snip, start


def scan(target: Path, excludes_csv: str = DEFAULT_EXCLUDES):
    """대상 폴더를 점검한다. 반환 dict: findings, engine, engine_version, files, lines, languages, excluded, duration."""
    engine, path = find_engine()
    if not engine:
        raise RuntimeError("정적분석 엔진(OpenGrep 또는 Semgrep)이 설치되어 있지 않습니다.")
    rules = rule_files()
    if not rules:
        raise RuntimeError(f"점검 규칙 파일이 없습니다: {RULES_DIR}")
    excludes = {e.strip() for e in excludes_csv.split(",") if e.strip()}

    # --no-git-ignore: 저장소 안(.gitignore 대상 storage/)에 풀린 소스도 빠짐없이 분석
    cmd = [path, "scan", "--json", "--quiet", "--no-git-ignore"]
    for r in rules:
        cmd += ["--config", str(r)]
    if engine == "semgrep":
        cmd += ["--metrics=off"]
    cmd.append(str(target))
    env = dict(os.environ, SEMGREP_SEND_METRICS="off", PYTHONUTF8="1")
    t0 = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", env=env, timeout=900)
    duration = time.time() - t0
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise RuntimeError(f"점검 엔진 실행 실패: {proc.stderr[-500:]}")

    messages = load_rule_messages()
    findings, seen = [], set()
    for r in data.get("results", []):
        check_id = r["check_id"]
        rule_id = check_id.split(".")[-1]
        file_abs = Path(r["path"])
        try:
            rel = str(file_abs.resolve().relative_to(target.resolve())).replace("\\", "/")
        except ValueError:
            rel = r["path"]
        if _excluded(rel, excludes):
            continue
        line, end_line = r["start"]["line"], r["end"]["line"]
        key = (rule_id, rel, line)
        if key in seen:
            continue
        seen.add(key)
        meta = messages.get(rule_id, {})
        md = r["extra"].get("metadata", {})
        cwe = meta.get("cwe") or (md.get("cwe")[0] if isinstance(md.get("cwe"), list) else md.get("cwe", ""))
        if cwe and ":" in str(cwe):
            cwe = str(cwe).split(":")[0].strip()
        code, snip, start = _snippet(file_abs, line, end_line)
        findings.append({
            "rule_id": rule_id,
            "cwe": cwe or "",
            "severity": meta.get("severity") or FALLBACK_SEVERITY.get(r["extra"].get("severity"), "Low"),
            "title": meta.get("name_ko") or rule_id,
            "cvss": str(meta.get("cvss", "")),
            "file": rel, "line": line, "end_line": end_line,
            "code": code, "snippet": snip, "snippet_start": start,
            "message": r["extra"].get("message", ""),
        })
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    findings.sort(key=lambda f: (order.get(f["severity"], 9), f["file"], f["line"]))
    files, lines, langs, excluded = inventory(target, excludes)
    return {"findings": findings, "engine": engine, "engine_version": engine_version(), "files": files,
            "lines": lines, "languages": langs, "excluded": excluded, "duration": round(duration, 1)}
