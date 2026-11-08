"""HTML → A4 PDF. 서버에 있는 Chrome/Chromium/Edge를 헤드리스로 실행한다(없으면 None → 브라우저 인쇄로 안내)."""
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

CANDIDATES = [
    os.getenv("MG_CHROME", ""),
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
]


def find_browser():
    for p in CANDIDATES:
        if p and Path(p).exists():
            return p
    for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
        p = shutil.which(name)
        if p:
            return p
    return None


def html_to_pdf(html: str, timeout=90):
    exe = find_browser()
    if not exe:
        return None
    tmp = Path(tempfile.mkdtemp(prefix="mg_pdf_"))
    src, out, prof = tmp / "doc.html", tmp / "doc.pdf", tmp / "profile"
    src.write_text(html, encoding="utf-8")
    cmd = [exe, "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check", "--no-sandbox",
           f"--user-data-dir={prof}", "--no-pdf-header-footer", "--virtual-time-budget=4000",
           f"--print-to-pdf={out}", src.as_uri()]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout)
        return out.read_bytes() if out.exists() and out.stat().st_size > 0 else None
    except (OSError, subprocess.SubprocessError):
        return None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
