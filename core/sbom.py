"""SBOM(소프트웨어 자재명세서) 생성과 알려진 취약점 조회.

- 구성요소 수집: 패키지 관리자 잠금·명세 파일(npm, PyPI, Go, Rust, Maven)과 펌웨어에 들어 있는
  임베디드 라이브러리(FreeRTOS, STM32 HAL, CMSIS, mbedTLS, lwIP, Zephyr 등)의 버전 매크로를 읽는다.
  서버에 Syft(오픈소스, Anchore)가 설치돼 있으면 그 결과를 합친다.
- 출력: CycloneDX 1.5 JSON (FDA §524B(b)(3) 기계판독 SBOM 형식)
- 취약점: OSV.dev(구글 오픈소스 취약점 DB) API로 purl 단위 조회. 임베디드 C 라이브러리는
  OSV에 패키지 단위 정보가 없어 「수동 확인」으로 표시하고 NVD 검색 링크를 준다.
"""
import json
import re
import shutil
import subprocess
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
SKIP_DIRS = {".git", "node_modules", "__pycache__", "venv", ".venv", "dist", "build"}


def _walk(root: Path, names):
    for p in root.rglob("*"):
        if p.is_file() and p.name in names and not any(part in SKIP_DIRS for part in p.relative_to(root).parts[:-1]):
            yield p


def _rel(root, p):
    return str(p.relative_to(root)).replace("\\", "/")


def _comp(name, version, eco, purl, src, license_="", scope="required", kind="library"):
    return {"name": name, "version": version or "", "ecosystem": eco, "purl": purl, "source": src,
            "license": license_ or "", "scope": scope, "type": kind}


# ── 패키지 관리자 ────────────────────────────────────────────
def _npm(root):
    out = []
    for lock in _walk(root, {"package-lock.json"}):
        try:
            d = json.loads(lock.read_text(encoding="utf-8", errors="replace"))
        except ValueError:
            continue
        src = _rel(root, lock)
        if "packages" in d:  # lockfile v2/v3
            for key, v in d["packages"].items():
                if not key or "version" not in v:
                    continue
                name = v.get("name") or key.split("node_modules/")[-1]
                out.append(_comp(name, v["version"], "npm", f"pkg:npm/{urllib.parse.quote(name, safe='@/')}@{v['version']}", src,
                                 v.get("license", ""), "optional" if v.get("dev") else "required"))
        else:  # v1
            def walk(deps):
                for name, v in (deps or {}).items():
                    if "version" in v and not str(v["version"]).startswith(("file:", "git")):
                        out.append(_comp(name, v["version"], "npm", f"pkg:npm/{urllib.parse.quote(name, safe='@/')}@{v['version']}", src,
                                         "", "optional" if v.get("dev") else "required"))
                    walk(v.get("dependencies"))
            walk(d.get("dependencies"))
    if not out:  # 잠금 파일이 없으면 package.json의 명시 버전만
        for pj in _walk(root, {"package.json"}):
            try:
                d = json.loads(pj.read_text(encoding="utf-8", errors="replace"))
            except ValueError:
                continue
            for sec, scope in (("dependencies", "required"), ("devDependencies", "optional")):
                for name, ver in (d.get(sec) or {}).items():
                    m = re.match(r"^[~^=v]?(\d+\.\d+\.\d+)", str(ver))
                    v = m.group(1) if m else ""
                    out.append(_comp(name, v, "npm", f"pkg:npm/{name}@{v}" if v else f"pkg:npm/{name}", _rel(root, pj), "", scope))
    return out


def _pypi(root):
    out = []
    for req in _walk(root, {"requirements.txt", "requirements-dev.txt", "requirements_dev.txt"}):
        for line in req.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.split("#")[0].strip()
            if not line or line.startswith(("-", "git+", "http")):
                continue
            m = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(==|>=|~=|<=|>|<)?\s*([A-Za-z0-9_.\-]+)?", line)
            if not m:
                continue
            name, op, ver = m.group(1), m.group(2), m.group(3)
            pinned = ver if op == "==" else ""
            norm = re.sub(r"[-_.]+", "-", name).lower()
            out.append(_comp(name, pinned or (f"{op}{ver}" if op else ""), "PyPI",
                             f"pkg:pypi/{norm}@{pinned}" if pinned else f"pkg:pypi/{norm}", _rel(root, req)))
    for lock in _walk(root, {"Pipfile.lock"}):
        try:
            d = json.loads(lock.read_text(encoding="utf-8"))
        except ValueError:
            continue
        for sec, scope in (("default", "required"), ("develop", "optional")):
            for name, v in (d.get(sec) or {}).items():
                ver = str(v.get("version", "")).lstrip("=")
                norm = re.sub(r"[-_.]+", "-", name).lower()
                out.append(_comp(name, ver, "PyPI", f"pkg:pypi/{norm}@{ver}", _rel(root, lock), "", scope))
    return out


def _go(root):
    out = []
    for gm in _walk(root, {"go.mod"}):
        for m in re.finditer(r"^\s*(?:require\s+)?([\w./\-]+\.[\w./\-]+)\s+(v[\w.\-+]+)", gm.read_text(errors="replace"), re.M):
            out.append(_comp(m.group(1), m.group(2), "Go", f"pkg:golang/{m.group(1)}@{m.group(2)}", _rel(root, gm)))
    return out


def _cargo(root):
    out = []
    for cl in _walk(root, {"Cargo.lock"}):
        for m in re.finditer(r'\[\[package\]\]\s*name\s*=\s*"([^"]+)"\s*version\s*=\s*"([^"]+)"', cl.read_text(errors="replace")):
            out.append(_comp(m.group(1), m.group(2), "crates.io", f"pkg:cargo/{m.group(1)}@{m.group(2)}", _rel(root, cl)))
    return out


def _maven(root):
    out = []
    for pom in _walk(root, {"pom.xml"}):
        t = pom.read_text(errors="replace")
        for m in re.finditer(r"<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<$]+)</version>", t):
            g, a, v = m.groups()
            out.append(_comp(f"{g}:{a}", v, "Maven", f"pkg:maven/{g}/{a}@{v}", _rel(root, pom)))
    return out


# ── 펌웨어 내장 라이브러리 (버전 매크로) ──────────────────────
def _macro(text, *names):
    vals = []
    for n in names:
        m = re.search(rf"#\s*define\s+{n}\s+\(?\s*(0x[0-9A-Fa-f]+|\d+)", text)
        if not m:
            return None
        vals.append(str(int(m.group(1), 16) if m.group(1).lower().startswith("0x") else int(m.group(1))))
    return ".".join(vals)


EMBEDDED = [
    # (이름, 공급자, 찾을 파일 이름 패턴, 버전 추출 함수, CPE 검색어, 라이선스)
    ("FreeRTOS Kernel", "Amazon / FreeRTOS", re.compile(r"^task\.h$"),
     lambda t: (re.search(r'tskKERNEL_VERSION_NUMBER\s+"V?([\d.]+)', t) or [None, None])[1], "freertos", "MIT"),
    ("STM32F4 HAL Driver", "STMicroelectronics", re.compile(r"^stm32f4xx_hal\.c$"),
     lambda t: _macro(t, "__STM32F4xx_HAL_VERSION_MAIN", "__STM32F4xx_HAL_VERSION_SUB1", "__STM32F4xx_HAL_VERSION_SUB2"), "stm32cube", "BSD-3-Clause"),
    ("CMSIS Core", "Arm", re.compile(r"^cmsis_version\.h$"),
     lambda t: _macro(t, "__CM_CMSIS_VERSION_MAIN", "__CM_CMSIS_VERSION_SUB"), "cmsis", "Apache-2.0"),
    ("STM32 USB Device Library", "STMicroelectronics", re.compile(r"^usbd_core\.c$"), lambda t: None, "stm32 usb device library", "BSD-3-Clause"),
    ("Mbed TLS", "Arm / TrustedFirmware", re.compile(r"^(build_info|version)\.h$"),
     lambda t: (re.search(r'MBEDTLS_VERSION_STRING\s+"([\d.]+)"', t) or [None, None])[1], "mbed_tls", "Apache-2.0"),
    ("lwIP", "Savannah lwIP", re.compile(r"^init\.h$"),
     lambda t: _macro(t, "LWIP_VERSION_MAJOR", "LWIP_VERSION_MINOR", "LWIP_VERSION_REVISION"), "lwip", "BSD-3-Clause"),
    ("BlueNRG-MS BLE Stack (X-CUBE-BLE1)", "STMicroelectronics", re.compile(r"^(bluenrg_gap|hci_le)\.h$"), lambda t: None, "bluenrg", "ST SLA"),
    ("STM32F4-Discovery BSP", "STMicroelectronics", re.compile(r"^stm32f4_discovery\.c$"),
     lambda t: _macro(t, "__STM32F4_DISCO_BSP_VERSION_MAIN", "__STM32F4_DISCO_BSP_VERSION_SUB1", "__STM32F4_DISCO_BSP_VERSION_SUB2"), "stm32f4 discovery bsp", "BSD-3-Clause"),
    ("STM324xG-EVAL BSP", "STMicroelectronics", re.compile(r"^stm324xg_eval\.c$"),
     lambda t: _macro(t, "__STM324xG_EVAL_BSP_VERSION_MAIN", "__STM324xG_EVAL_BSP_VERSION_SUB1", "__STM324xG_EVAL_BSP_VERSION_SUB2"), "stm324xg eval bsp", "BSD-3-Clause"),
    ("libopencm3", "libopencm3 project", re.compile(r"^(common|memorymap)\.h$"), lambda t: None, "libopencm3", "LGPL-3.0"),
    ("TinyCrypt", "Intel", re.compile(r"^tinycrypt.*\.h$|^aes\.h$"), lambda t: None, "tinycrypt", "BSD-3-Clause"),
]


def _embedded(root):
    found = {}
    for p in root.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in (".h", ".c"):
            continue
        for name, supplier, pat, ver_fn, cpe, lic in EMBEDDED:
            if not pat.match(p.name):
                continue
            if name in ("Mbed TLS",) and "mbedtls" not in str(p).lower():
                continue
            if name == "lwIP" and "lwip" not in str(p).lower():
                continue
            if name == "TinyCrypt" and "tinycrypt" not in str(p).lower():
                continue
            if name == "libopencm3" and "libopencm3" not in str(p).lower():
                continue
            try:
                ver = ver_fn(p.read_text(encoding="utf-8", errors="replace")) or ""
            except OSError:
                ver = ""
            key = (name, ver)
            if key in found:
                continue
            slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
            c = _comp(name, ver, "임베디드(C)", f"pkg:generic/{slug}@{ver}" if ver else f"pkg:generic/{slug}", _rel(root, p), lic)
            c["supplier"] = supplier
            c["nvd"] = "https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=" + urllib.parse.quote(f"{cpe} {ver}".strip())
            found[key] = c
    # 버전 없는 항목은 같은 이름의 버전 있는 항목이 있으면 뺀다
    names_with_ver = {n for (n, v) in found if v}
    return [c for (n, v), c in found.items() if v or n not in names_with_ver]


def _syft(root):
    exe = shutil.which("syft")
    if not exe:
        return [], None
    try:
        r = subprocess.run([exe, f"dir:{root}", "-o", "cyclonedx-json", "-q"], capture_output=True, text=True, timeout=600)
        d = json.loads(r.stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        return [], None
    out = []
    for c in d.get("components", []):
        purl = c.get("purl", "")
        eco = purl.split("/")[0].replace("pkg:", "") if purl else c.get("type", "")
        lic = ", ".join(l.get("license", {}).get("id") or l.get("license", {}).get("name", "") for l in c.get("licenses", []) if "license" in l)
        out.append(_comp(c.get("name", ""), c.get("version", ""), eco, purl, "syft", lic))
    return out, "Syft"


# ── OSV.dev 취약점 조회 ─────────────────────────────────────
def _post(url, body, timeout=30):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json",
                                                                               "User-Agent": "MediGuide-SBOM/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def _get(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "MediGuide-SBOM/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def _severity(v):
    ds = (v.get("database_specific") or {}).get("severity")
    if ds:
        return {"CRITICAL": "Critical", "HIGH": "High", "MODERATE": "Medium", "MEDIUM": "Medium", "LOW": "Low"}.get(str(ds).upper(), str(ds).title())
    for s in v.get("severity", []):
        m = re.search(r"/AV:", s.get("score", ""))
        if m:
            return "확인 필요"
    return "확인 필요"


def _fixed(v, purl):
    for a in v.get("affected", []):
        if (a.get("package") or {}).get("purl", "").split("@")[0] not in ("", purl.split("@")[0]):
            continue
        for r in a.get("ranges", []):
            for e in r.get("events", []):
                if "fixed" in e:
                    return e["fixed"]
    return ""


def query_osv(components):
    """반환: (구성요소별 취약점 ID 목록 dict, 취약점 상세 dict, 오류 문자열)."""
    targets = [c for c in components if "@" in c["purl"] and not c["purl"].startswith("pkg:generic/")]
    hits, details, err = {}, {}, ""
    try:
        for i in range(0, len(targets), 500):
            chunk = targets[i:i + 500]
            res = _post(OSV_BATCH, {"queries": [{"package": {"purl": c["purl"]}} for c in chunk]})
            for c, r in zip(chunk, res.get("results", [])):
                ids = [v["id"] for v in r.get("vulns", [])]
                if ids:
                    hits[c["purl"]] = ids
        uniq = sorted({i for ids in hits.values() for i in ids})[:400]

        def fetch(vid):
            try:
                return vid, _get(OSV_VULN + vid)
            except Exception:  # noqa: BLE001
                return vid, None
        with ThreadPoolExecutor(8) as ex:
            for vid, v in ex.map(fetch, uniq):
                if not v:
                    details[vid] = {"id": vid, "summary": "", "severity": "확인 필요", "aliases": [], "fixed": {}}
                    continue
                details[vid] = {"id": vid, "summary": (v.get("summary") or v.get("details", "")[:160]).strip(),
                                "severity": _severity(v), "aliases": [a for a in v.get("aliases", []) if a.startswith("CVE-")],
                                "published": (v.get("published") or "")[:10],
                                "fixed": {p: _fixed(v, p) for p, ids in hits.items() if vid in ids}}
    except Exception as e:  # noqa: BLE001 — 오프라인이어도 SBOM은 만든다
        err = f"OSV.dev 조회 실패: {e}"
    return hits, details, err


# ── 생성 ─────────────────────────────────────────────────────
def generate(root: Path, query_vulns=True):
    comps = _npm(root) + _pypi(root) + _go(root) + _cargo(root) + _maven(root) + _embedded(root)
    syft_comps, tool = _syft(root)
    have = {c["purl"] for c in comps}
    comps += [c for c in syft_comps if c["purl"] and c["purl"] not in have]
    # 같은 purl 중복 제거
    seen, uniq = set(), []
    for c in comps:
        k = c["purl"] or (c["name"], c["version"])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(c)
    hits, details, err = query_osv(uniq) if query_vulns else ({}, {}, "취약점 조회 꺼짐")
    for c in uniq:
        c["vulns"] = hits.get(c["purl"], [])
    return {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tools": ["메디가이드 SBOM 수집기 1.0"] + ([tool] if tool else []) + ["OSV.dev"],
            "components": uniq, "vulns": details, "error": err}


def summary(s):
    comps = s.get("components", [])
    vulnerable = [c for c in comps if c.get("vulns")]
    sev = {}
    for v in s.get("vulns", {}).values():
        sev[v["severity"]] = sev.get(v["severity"], 0) + 1
    ecos = {}
    for c in comps:
        ecos[c["ecosystem"]] = ecos.get(c["ecosystem"], 0) + 1
    return {"n": len(comps), "vulnerable": len(vulnerable), "n_vulns": len(s.get("vulns", {})), "sev": sev, "ecos": ecos,
            "no_version": sum(1 for c in comps if not c["version"]), "no_license": sum(1 for c in comps if not c["license"]),
            "manual": sum(1 for c in comps if c["ecosystem"] == "임베디드(C)")}


def to_cyclonedx(s, dev, scan):
    comps = []
    for c in s.get("components", []):
        e = {"type": c.get("type", "library"), "name": c["name"], "version": c["version"] or "unknown",
             "bom-ref": c["purl"] or f"{c['name']}@{c['version']}", "scope": c.get("scope", "required")}
        if c["purl"]:
            e["purl"] = c["purl"]
        if c.get("license"):
            e["licenses"] = [{"license": {"id": c["license"]}}] if re.match(r"^[A-Za-z0-9.\-+]+$", c["license"]) \
                else [{"license": {"name": c["license"]}}]
        if c.get("supplier"):
            e["supplier"] = {"name": c["supplier"]}
        e["properties"] = [{"name": "mediguide:source", "value": c.get("source", "")}]
        comps.append(e)
    vulns = []
    for vid, v in s.get("vulns", {}).items():
        affects = [{"ref": p} for p in v.get("fixed", {})]
        item = {"id": vid, "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{vid}"},
                "description": v.get("summary", ""), "affects": affects}
        if v.get("severity") in ("Critical", "High", "Medium", "Low"):
            item["ratings"] = [{"severity": v["severity"].lower(), "source": {"name": "OSV"}}]
        if v.get("aliases"):
            item["references"] = [{"id": a, "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{a}"}} for a in v["aliases"]]
        vulns.append(item)
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, scan['code'] + s['generated_at'])}",
        "metadata": {"timestamp": s["generated_at"],
                     "tools": [{"vendor": "8팀 무한루프", "name": t} for t in s.get("tools", [])],
                     "component": {"type": "firmware" if dev.get("fw_version") else "application", "name": dev.get("name_en") or dev["name"],
                                   "version": scan.get("version") or dev.get("sw_version") or "", "bom-ref": dev["code"]},
                     "manufacture": {"name": dev.get("maker_en") or dev.get("maker") or ""}},
        "components": comps, "vulnerabilities": vulns,
    }
