from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, HttpUrl
from pathlib import Path
from urllib.parse import urlparse
import asyncio, json, re, shutil, zipfile, hashlib, mimetypes, uuid, os, base64, sys, pathlib
from datetime import datetime, timezone
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

FROZEN = bool(getattr(sys, "frozen", False))
RESOURCE_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
APP_DIR = Path(sys.executable).resolve().parent if FROZEN else Path(__file__).resolve().parent
DATA = APP_DIR / "projects"
DATA.mkdir(exist_ok=True)
CONFIG_PATH = APP_DIR / "config.json"
DEFAULT_CONFIG = {
    "app_name": "jWebDebugger Studio", "version": "1.6.1",
    "server": {"host": "127.0.0.1", "port": 8765},
    "capture": {"default_wait_seconds": 4, "navigation_timeout_ms": 45000,
                "network_idle_timeout_ms": 10000, "max_wait_seconds": 30},
    "diagnostics": {"capture_response_headers": True, "flag_http_errors": True},
    "offline": {"enable_single_html": True, "embed_images": True,
                "embed_css": True, "embed_javascript": True},
    "interface": {"theme": "dark", "auto_refresh": True, "activity_poll_ms": 1200}
}
def load_config():
    if not CONFIG_PATH.exists():
        CONFIG_PATH.write_text(json.dumps(DEFAULT_CONFIG, indent=2), encoding="utf-8")
    try:
        user_cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        merged = json.loads(json.dumps(DEFAULT_CONFIG))
        for key, value in user_cfg.items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key].update(value)
            else:
                merged[key] = value
        return merged
    except Exception:
        return json.loads(json.dumps(DEFAULT_CONFIG))
CONFIG = load_config()
STATIC_DIR = APP_DIR / "static"
if not STATIC_DIR.is_dir():
    STATIC_DIR = RESOURCE_DIR / "static"
app = FastAPI(title="jWebDebugger Studio", version="1.6.1")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
ACTIVE_ACTIVITY = {"state": "idle", "message": "Ready", "url": "", "started": None,
                   "requests": 0, "http_errors": 0, "last_event": ""}

class CaptureRequest(BaseModel):
    url: str
    project_name: str = "Website capture"
    wait_seconds: float | None = None
    full_page: bool = True

class LocalImportRequest(BaseModel):
    project_name: str = "Local HTML project"
    index_file: str = "index.html"
    html: str
    files: list[dict] = []
    base_url: str = ""

def safe_name(value):
    return re.sub(r"[^a-zA-Z0-9_-]+", "-", value).strip("-_")[:60] or "capture"

def project_dir(pid):
    p = DATA / pid
    if not p.exists():
        raise HTTPException(404, "Project not found")
    return p

def read_manifest(p):
    f = p / "manifest.json"
    return json.loads(f.read_text("utf-8")) if f.exists() else {}

def write_manifest(p, data):
    (p / "manifest.json").write_text(json.dumps(data, indent=2), encoding="utf-8")

@app.get("/", response_class=HTMLResponse)
async def home():
    return FileResponse(STATIC_DIR / "index.html")

@app.get("/api/health")
async def health():
    browser_ready = False
    try:
        browser_ready = bool(list((APP_DIR / "ms-playwright").glob("chromium*"))) or not FROZEN
    except Exception:
        pass
    return {"ok": True, "version": "1.6.1", "browser_runtime": browser_ready,
            "projects_writable": os.access(DATA, os.W_OK)}

@app.get("/api/config")
async def get_config():
    return CONFIG

@app.post("/api/config/reload")
async def reload_config():
    global CONFIG
    CONFIG = load_config()
    return {"ok": True, "config": CONFIG}

@app.get("/api/activity")
async def activity():
    return ACTIVE_ACTIVITY

@app.get("/api/projects/{pid}/diagnostics")
async def project_diagnostics(pid: str):
    p = project_dir(pid)
    m = read_manifest(p)
    resources = m.get("resources", [])
    errors = m.get("errors", [])
    page_errors = m.get("page_errors", [])
    statuses = [int(r.get("status") or 0) for r in resources]
    http_errors = [r for r in resources if int(r.get("status") or 0) >= 400]
    server_errors = [r for r in resources if int(r.get("status") or 0) >= 500]
    client_errors = [r for r in resources if 400 <= int(r.get("status") or 0) < 500]
    redirects = [r for r in resources if 300 <= int(r.get("status") or 0) < 400]
    findings = []
    for r in server_errors:
        findings.append({"severity": "critical", "code": "HTTP_5XX",
                         "message": f"Server returned HTTP {r.get('status')} for {r.get('url')}",
                         "suggestion": "Inspect server application logs, reverse-proxy logs, upstream health and request correlation IDs. This capture cannot inspect private server logs."})
    for r in client_errors:
        status_code = int(r.get("status") or 0)
        msg = "Authentication/authorization may be required." if status_code in (401, 403) else (
              "Rate limiting may be active." if status_code == 429 else "The requested resource was rejected or not found.")
        findings.append({"severity": "warning", "code": f"HTTP_{status_code}",
                         "message": f"HTTP {status_code}: {r.get('url')}",
                         "suggestion": msg + " Verify credentials, permissions, route and server policy; do not attempt to bypass access controls."})
    for e in errors:
        findings.append({"severity": "warning", "code": "REQUEST_FAILURE",
                         "message": str(e.get("error", e)), "suggestion": "Check DNS, TLS, timeout, proxy and network connectivity."})
    for e in page_errors[:100]:
        findings.append({"severity": "info", "code": "BROWSER_CONSOLE",
                         "message": str(e), "suggestion": "Inspect the referenced script, source map and browser console context."})
    return {"project_id": pid, "resource_count": len(resources),
            "http_errors": len(http_errors), "server_errors": len(server_errors),
            "client_errors": len(client_errors), "redirects": len(redirects),
            "request_failures": len(errors), "console_errors": len(page_errors),
            "findings": findings,
            "note": "Client-side capture cannot prove server-side root cause. Correlate timestamps/request IDs with authorized server logs."}



async def capture_project_dependencies(pid: str, wait_seconds: float = 4.0):
    """Open an imported local page in Chromium and capture all browser-observed responses."""
    p = project_dir(pid)
    manifest = read_manifest(p)
    index_file = manifest.get("index_file") or "index.html"
    port = int(CONFIG.get("server", {}).get("port", 8765))
    start_url = f"http://127.0.0.1:{port}/api/projects/{pid}/site/{index_file}"
    manifest["url"] = start_url
    manifest["final_url"] = start_url
    resources_dir = p / "resources"
    resources_dir.mkdir(exist_ok=True)
    records = manifest.setdefault("resources", [])
    errors = manifest.setdefault("errors", [])
    page_errors = manifest.setdefault("page_errors", [])
    existing_urls = {r.get("url") for r in records}
    seen_hashes = {}
    tasks = []

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context(ignore_https_errors=False)
        page = await context.new_page()
        page.on("pageerror", lambda exc: page_errors.append(str(exc)))
        page.on("console", lambda msg: page_errors.append("console.error: " + msg.text) if msg.type == "error" else None)

        async def save_response(response):
            try:
                url = response.url
                if url in existing_urls:
                    return
                headers = await response.all_headers()
                body = await response.body()
                digest = hashlib.sha256(body).hexdigest()
                if digest in seen_hashes:
                    filename = seen_hashes[digest]
                else:
                    ctype = headers.get("content-type", "")
                    ext = mimetypes.guess_extension(ctype.split(";")[0].strip()) or ""
                    if ext == ".jpe":
                        ext = ".jpg"
                    if not ext:
                        ext = Path(urlparse(url).path).suffix[:12] or ".bin"
                    filename = digest[:20] + ext
                    (resources_dir / filename).write_bytes(body)
                    seen_hashes[digest] = filename
                rec = {
                    "url": url, "status": response.status,
                    "content_type": headers.get("content-type", ""),
                    "resource_type": response.request.resource_type,
                    "method": response.request.method, "size": len(body),
                    "sha256": digest, "file": "resources/" + filename,
                    "from_service_worker": getattr(response, "from_service_worker", False)
                }
                records.append(rec)
                existing_urls.add(url)
            except Exception as exc:
                errors.append({"url": response.url, "error": str(exc)})

        page.on("response", lambda response: tasks.append(asyncio.create_task(save_response(response))))
        try:
            await page.goto(start_url, wait_until="domcontentloaded", timeout=45000)
            await page.wait_for_timeout(max(0, min(wait_seconds, 20)) * 1000)
            try:
                await page.wait_for_load_state("networkidle", timeout=8000)
            except Exception:
                pass
        except Exception as exc:
            errors.append({"url": start_url, "error": str(exc)})
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        await browser.close()

    write_manifest(p, manifest)
    return {
        "captured_resources": len(records),
        "newly_captured": len([r for r in records if r.get("url") not in {
            (manifest.get("url") or "")}]),
        "failed_requests": len(errors),
        "page_errors": len(page_errors)
    }

@app.post("/api/import-local")
async def import_local(req: LocalImportRequest):
    """Import local HTML/files first; dependency discovery is a separate best-effort step."""
    global ACTIVE_ACTIVITY
    pid = uuid.uuid4().hex[:12]
    local_source_label = req.base_url.strip() or ("local:///" + req.index_file.replace("\\\\", "/").lstrip("/"))
    ACTIVE_ACTIVITY = {"state": "importing", "message": "Saving local website files",
                       "url": local_source_label, "started": datetime.now(timezone.utc).isoformat(),
                       "requests": 0, "http_errors": 0, "last_event": "Local file import"}
    p = DATA / pid
    p.mkdir(parents=True)
    original_index_path = req.index_file.replace("\\", "/").lstrip("/")
    if ".." in Path(original_index_path).parts:
        raise HTTPException(400, "Invalid index filename")
    parent = str(Path(original_index_path).parent).replace("\\", "/")
    if parent == ".":
        parent = ""
    # Imported files are stored relative to the selected index page, so serve it at the site root.
    index_file = Path(original_index_path).name
    saved_files = []
    total_bytes = len(req.html.encode("utf-8"))
    for item in req.files:
        rel = str(item.get("path", "")).replace("\\", "/").lstrip("/")
        if not rel or ".." in Path(rel).parts:
            continue
        # Keep paths relative to the selected index.html so its relative links still resolve.
        if parent:
            if rel == parent:
                continue
            if rel.startswith(parent + "/"):
                rel = rel[len(parent) + 1:]
            else:
                continue
        try:
            raw = base64.b64decode(item.get("data", ""), validate=True)
        except Exception:
            continue
        total_bytes += len(raw)
        if total_bytes > 100 * 1024 * 1024:
            shutil.rmtree(p, ignore_errors=True)
            raise HTTPException(413, "Import exceeds the 100 MB V1 limit")
        dest = (p / rel).resolve()
        if p.resolve() not in dest.parents:
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(raw)
        saved_files.append({"path": rel, "size": len(raw)})
    (p / "original.html").write_text(req.html, encoding="utf-8")
    records = []
    for item in saved_files:
        f = p / item["path"]
        mime = mimetypes.guess_type(f.name)[0] or "application/octet-stream"
        records.append({
            "url": (req.base_url.rstrip("/") + "/" + item["path"]) if req.base_url else "local:///" + item["path"],
            "status": 200, "content_type": mime, "resource_type": "local-file",
            "method": "LOCAL", "size": item["size"], "sha256": hashlib.sha256(f.read_bytes()).hexdigest(),
            "file": item["path"], "from_service_worker": False
        })
    manifest = {
        "id": pid, "name": req.project_name, "url": req.base_url or "Local HTML import",
        "final_url": req.base_url or "local:///" + index_file,
        "created": datetime.now(timezone.utc).isoformat(),
        "resources": records, "errors": [], "page_errors": [],
        "source_type": "local", "index_file": index_file,
        "local_files": saved_files,
        "notes": ["Imported from local HTML source/folder.", "Relative asset paths are preserved when the selected index file is at the selected folder root or within the selected folder."]
    }
    write_manifest(p, manifest)
    # Local files are now safely persisted. Browser discovery is best-effort and must
    # never roll back or hide a valid local import when Chromium is unavailable.
    capture_result = {
        "status": "skipped", "captured_resources": len(records),
        "failed_requests": 0, "page_errors": 0,
        "message": "Local files imported; browser dependency discovery was not run."
    }
    try:
        ACTIVE_ACTIVITY.update({"state": "discovering", "message": "Discovering local page dependencies",
                                "last_event": "Launching Chromium"})
        capture_result = await capture_project_dependencies(pid, wait_seconds=4.0)
        capture_result["status"] = "complete"
        capture_result["message"] = "Local import and browser dependency discovery completed."
        ACTIVE_ACTIVITY.update({"state": "complete", "message": "Local import complete",
                                "last_event": local_source_label})
    except Exception as exc:
        # Keep the imported project intact and record the discovery problem for inspection.
        discovery_error = str(exc)[:1000]
        manifest = read_manifest(p)
        manifest.setdefault("errors", []).append({
            "url": local_source_label,
            "error": "Optional browser dependency discovery failed: " + discovery_error
        })
        manifest["dependency_discovery"] = {
            "status": "failed", "error": discovery_error,
            "note": "The local HTML and selected files were imported and remain available."
        }
        write_manifest(p, manifest)
        capture_result = {
            "status": "failed", "captured_resources": len(manifest.get("resources", [])),
            "failed_requests": 1, "page_errors": 0,
            "message": "Local files were imported, but automatic dependency discovery failed: " + discovery_error
        }
        ACTIVE_ACTIVITY.update({"state": "complete_with_warning",
                                "message": "Local import complete · dependency discovery needs attention",
                                "last_event": discovery_error})
    manifest = read_manifest(p)
    return {"id": pid, "name": req.project_name, "resource_count": len(manifest.get("resources", [])),
            "files_imported": len(saved_files), "source_type": "local",
            "capture": capture_result}

@app.get("/api/projects")
async def projects():
    out = []
    for p in DATA.iterdir():
        if p.is_dir() and (p / "manifest.json").exists():
            m = read_manifest(p)
            out.append({"id": p.name, "name": m.get("name"), "url": m.get("url"),
                        "created": m.get("created"), "resources": len(m.get("resources", []))})
    return sorted(out, key=lambda x: x.get("created", ""), reverse=True)

@app.get("/api/projects/{pid}")
async def project_detail(pid: str):
    """Return a project's manifest for the dashboard inspector."""
    p = project_dir(pid)
    manifest_file = p / "manifest.json"
    if not manifest_file.is_file():
        raise HTTPException(404, "Project manifest not found")
    manifest = read_manifest(p)
    if not manifest:
        raise HTTPException(500, "Project manifest is empty or invalid")
    return manifest

@app.post("/api/capture")
async def capture(req: CaptureRequest):
    global ACTIVE_ACTIVITY
    parsed = urlparse(req.url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise HTTPException(400, "Enter a valid HTTP or HTTPS URL")
    pid = uuid.uuid4().hex[:12]
    p = DATA / pid
    resources_dir = p / "resources"
    resources_dir.mkdir(parents=True)
    records, errors, seen = [], [], {}
    main_html = ""
    final_url = req.url

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context(ignore_https_errors=False)
        page = await context.new_page()
        page_errors = []
        page.on("pageerror", lambda exc: page_errors.append(str(exc)))
        page.on("console", lambda msg: page_errors.append("console." + msg.type + ": " + msg.text) if msg.type == "error" else None)

        async def on_response(response):
            nonlocal main_html, final_url
            try:
                req_obj = response.request
                url = response.url
                headers = await response.all_headers()
                content_type = headers.get("content-type", "")
                status = response.status
                body = await response.body()
                if req_obj.resource_type == "document" and (url == req.url or not main_html):
                    try:
                        main_html = body.decode(headers.get("content-encoding-decoded", "utf-8"), errors="replace")
                    except Exception:
                        main_html = body.decode("utf-8", errors="replace")
                    final_url = url
                digest = hashlib.sha256(body).hexdigest()
                if digest not in seen:
                    ext = mimetypes.guess_extension(content_type.split(";")[0].strip()) or ""
                    if ext == ".jpe": ext = ".jpg"
                    if not ext:
                        path_ext = Path(urlparse(url).path).suffix
                        ext = path_ext[:12] if path_ext else ".bin"
                    filename = digest[:20] + ext
                    (resources_dir / filename).write_bytes(body)
                    seen[digest] = filename
                filename = seen[digest]
                ACTIVE_ACTIVITY["requests"] = len(records) + 1
                if status >= 400:
                    ACTIVE_ACTIVITY["http_errors"] = ACTIVE_ACTIVITY.get("http_errors", 0) + 1
                ACTIVE_ACTIVITY["state"] = "capturing"
                ACTIVE_ACTIVITY["message"] = f"Received HTTP {status} · {req_obj.resource_type}"
                ACTIVE_ACTIVITY["last_event"] = url
                records.append({
                    "url": url, "status": status, "content_type": content_type,
                    "resource_type": req_obj.resource_type, "method": req_obj.method,
                    "size": len(body), "sha256": digest, "file": "resources/" + filename,
                    "from_service_worker": getattr(response, "from_service_worker", False)
                })
            except Exception as exc:
                errors.append({"url": response.url, "error": str(exc)})

        page.on("response", lambda response: asyncio.create_task(on_response(response)))
        try:
            ACTIVE_ACTIVITY["state"] = "navigating"
            ACTIVE_ACTIVITY["message"] = "Navigating to target"
            await page.goto(req.url, wait_until="domcontentloaded",
                            timeout=int(CONFIG["capture"].get("navigation_timeout_ms", 45000)))
            ACTIVE_ACTIVITY["state"] = "capturing"
            ACTIVE_ACTIVITY["message"] = "Collecting page resources"
            wait_seconds = CONFIG["capture"].get("default_wait_seconds", 4) if req.wait_seconds is None else req.wait_seconds
            await page.wait_for_timeout(max(0, min(float(wait_seconds), int(CONFIG["capture"].get("max_wait_seconds", 30)))) * 1000)
            try:
                await page.wait_for_load_state("networkidle", timeout=int(CONFIG["capture"].get("network_idle_timeout_ms", 10000)))
            except Exception:
                pass
            final_url = page.url
            try:
                main_html = await page.content()
            except Exception:
                pass
        except Exception as exc:
            errors.append({"url": req.url, "error": str(exc)})
            if not main_html:
                await browser.close()
                shutil.rmtree(p, ignore_errors=True)
                ACTIVE_ACTIVITY.update({"state": "failed", "message": str(exc), "last_event": req.url})
                raise HTTPException(502, f"Navigation failed: {exc}")
        # allow queued response handlers to finish
        await page.wait_for_timeout(500)
        await browser.close()

    if not main_html:
        raise HTTPException(502, "The page returned no HTML document")
    (p / "original.html").write_text(main_html, encoding="utf-8")
    manifest = {
        "id": pid, "name": req.project_name, "url": req.url, "final_url": final_url,
        "created": datetime.now(timezone.utc).isoformat(),
        "resources": records, "errors": errors, "page_errors": page_errors,
        "notes": ["Network capture is a snapshot of observed responses, not a guarantee of offline equivalence.",
                  "Authenticated APIs, server-side operations, WebSockets, streaming and runtime-generated URLs may need manual handling."]
    }
    write_manifest(p, manifest)
    ACTIVE_ACTIVITY.update({"state": "complete", "message": "Capture complete",
                            "last_event": final_url, "requests": len(records),
                            "http_errors": len([r for r in records if int(r.get("status") or 0) >= 400])})
    return {"id": pid, "name": req.project_name, "url": final_url,
            "resource_count": len(records), "errors": errors, "page_errors": page_errors}


def _canonical_url(value, base_url=None):
    """Normalize a resource URL for matching; fragments never identify a fetched resource."""
    from urllib.parse import urljoin, urlsplit, urlunsplit
    absolute = urljoin(base_url or "", value)
    parts = urlsplit(absolute)
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", parts.query, ""))


def _valid_resource_record(project_path, rec):
    """Only map successful, non-empty files whose bytes match the manifest digest."""
    try:
        status = int(rec.get("status", 0))
        if status < 200 or status >= 300:
            return False
        rel = str(rec.get("file") or "").replace("\\", "/")
        if not rel or ".." in pathlib.PurePosixPath(rel).parts:
            return False
        f = (project_path / rel).resolve()
        if project_path.resolve() not in f.parents or not f.is_file() or f.stat().st_size <= 0:
            return False
        expected = rec.get("sha256")
        if expected:
            h = hashlib.sha256(f.read_bytes()).hexdigest()
            if h != expected:
                return False
        return True
    except Exception:
        return False


def url_to_file_map(manifest, project_path=None):
    """Map only valid successful responses. Failed HTTP bodies are never treated as assets."""
    mapping = {}
    base = manifest.get("final_url") or manifest.get("url") or ""
    for rec in manifest.get("resources", []):
        if not rec.get("url") or not rec.get("file"):
            continue
        if project_path is not None and not _valid_resource_record(project_path, rec):
            continue
        if project_path is None:
            try:
                if int(rec.get("status", 0)) < 200 or int(rec.get("status", 0)) >= 300 or int(rec.get("size", 0)) <= 0:
                    continue
            except Exception:
                continue
        mapping[_canonical_url(rec["url"], base)] = rec["file"].replace("\\", "/")
    return mapping


def _local_relative_path(file_value, from_css=False):
    rel = str(file_value).replace("\\", "/")
    if rel.startswith("resources/"):
        rel = rel[len("resources/"):]
    return rel


def patch_css(css, base_url, mapping):
    """Rewrite CSS url() and @import references relative to the original stylesheet URL."""
    def local_for(raw):
        return mapping.get(_canonical_url(raw, base_url))
    def replace_url(match):
        raw = match.group(2).strip().strip("\"'")
        local = local_for(raw)
        if not local:
            return match.group(0)
        return "url(" + (match.group(1) or "") + _local_relative_path(local, True) + (match.group(1) or "") + ")"
    css = re.sub(r"url\(\s*([\"']?)(.*?)\1\s*\)", replace_url, css, flags=re.I)
    def replace_import(match):
        raw = match.group(2).strip()
        local = local_for(raw)
        return match.group(1) + (_local_relative_path(local, True) if local else raw) + match.group(3)
    return re.sub(r"(@import\s+[\"'])([^\"']+)([\"'])", replace_import, css, flags=re.I)


def patch_inline_css(css, base_url, mapping):
    """Rewrite inline CSS references relative to the HTML document."""
    def replace_url(match):
        raw = match.group(2).strip().strip("\"'")
        local = mapping.get(_canonical_url(raw, base_url))
        if not local:
            return match.group(0)
        quote = match.group(1) or ""
        return "url(" + quote + str(local).replace("\\", "/") + quote + ")"
    return re.sub(r"url\(\s*([\"']?)(.*?)\1\s*\)", replace_url, css, flags=re.I)


def build_offline(pid):
    p = project_dir(pid)
    m = read_manifest(p)
    base_url = m.get("final_url") or m.get("url") or ""
    mapping = url_to_file_map(m, p)

    # Work on copies. Never mutate the original captured response files.
    css_outputs = {}
    for rec in m.get("resources", []):
        ctype = (rec.get("content_type") or "").lower()
        if "text/css" not in ctype or not _valid_resource_record(p, rec):
            continue
        source_file = p / rec["file"]
        try:
            css_text = source_file.read_text("utf-8", errors="replace")
            css_outputs[rec["file"]] = patch_css(css_text, rec["url"], mapping)
        except Exception:
            continue

    original = p / "original.html"
    if not original.is_file():
        raise HTTPException(400, "Original HTML is missing; recapture this project.")
    html = original.read_text("utf-8", errors="replace")
    soup = BeautifulSoup(html, "html.parser")
    unresolved = []
    rewritten = []
    missing_files = []
    resource_status_errors = []

    for rec in m.get("resources", []):
        try:
            status = int(rec.get("status", 0))
        except Exception:
            status = 0
        if status >= 400:
            resource_status_errors.append({
                "url": rec.get("url"), "status": status,
                "resource_type": rec.get("resource_type"), "content_type": rec.get("content_type")
            })

    # A <base> element would make relative resources resolve against the live website.
    for base_tag in soup.find_all("base"):
        base_tag.decompose()

    attrs = [("script", "src"), ("link", "href"), ("img", "src"),
             ("source", "src"), ("video", "poster"), ("audio", "src"),
             ("iframe", "src"), ("embed", "src"), ("input", "src")]
    for tag_name, attr in attrs:
        for tag in soup.find_all(tag_name):
            value = tag.get(attr)
            if not value or str(value).startswith(("data:", "blob:", "javascript:", "#")):
                continue
            absolute = _canonical_url(str(value), base_url)
            local = mapping.get(absolute)
            if local:
                tag[attr] = str(local).replace("\\", "/")
                rewritten.append({"tag": tag_name, "attribute": attr, "original": absolute, "local": tag[attr]})
                if tag_name == "script":
                    tag.attrs.pop("integrity", None)
                    tag.attrs.pop("crossorigin", None)
            elif urlparse(absolute).scheme in ("http", "https"):
                unresolved.append({"tag": tag_name, "attribute": attr, "url": absolute})

    for tag in soup.find_all(srcset=True):
        candidates = []
        for candidate in tag["srcset"].split(","):
            bits = candidate.strip().split()
            if not bits:
                continue
            absolute = _canonical_url(bits[0], base_url)
            local = mapping.get(absolute)
            if local:
                bits[0] = str(local).replace("\\", "/")
                rewritten.append({"tag": tag.name, "attribute": "srcset", "original": absolute, "local": bits[0]})
            elif urlparse(absolute).scheme in ("http", "https"):
                unresolved.append({"tag": tag.name, "attribute": "srcset", "url": absolute})
            candidates.append(" ".join(bits))
        tag["srcset"] = ", ".join(candidates)

    for tag in soup.find_all(style=True):
        tag["style"] = patch_inline_css(tag["style"], base_url, mapping)
    for style in soup.find_all("style"):
        css = style.string or style.get_text()
        style.string = patch_inline_css(css, base_url, mapping)

    # CSS files are rewritten in place only in the offline package tree; source captures remain intact.
    offline_dir = p / "offline"
    resources_out = offline_dir / "resources"
    resources_out.mkdir(parents=True, exist_ok=True)
    for rec in m.get("resources", []):
        if not _valid_resource_record(p, rec):
            continue
        rel = str(rec["file"]).replace("\\", "/")
        target_rel = pathlib.PurePosixPath(rel)
        if target_rel.is_absolute() or ".." in target_rel.parts:
            continue
        target = offline_dir.joinpath(*target_rel.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        if rel in css_outputs:
            target.write_text(css_outputs[rel], encoding="utf-8")
        else:
            shutil.copy2(p / rel, target)

    # HTML uses resources/<hash> paths, so offline.html sits beside the resources directory.
    offline_html = offline_dir / "offline.html"
    offline_html.write_text(str(soup), encoding="utf-8")

    # Validate every rewritten path against the actual output tree.
    for item in rewritten:
        rel = pathlib.PurePosixPath(item["local"])
        target = offline_dir.joinpath(*rel.parts)
        if not target.is_file() or target.stat().st_size <= 0:
            missing_files.append({"url": item["original"], "local": item["local"]})

    report = {
        "project": pid,
        "captured_resource_records": len(m.get("resources", [])),
        "valid_resources": len(mapping),
        "invalid_or_failed_resource_records": len(m.get("resources", [])) - len(mapping),
        "rewritten_references": len(rewritten),
        "rewritten_reference_details": rewritten,
        "unresolved_references": unresolved,
        "missing_local_files": missing_files,
        "http_response_errors": resource_status_errors,
        "failed_requests": m.get("errors", []),
        "page_errors": m.get("page_errors", []),
        "offline_build_passed": not unresolved and not missing_files,
        "limitations": [
            "JavaScript strings, dynamic import expressions and computed URLs are not rewritten automatically.",
            "API responses are captured as evidence but are not replayed as a functioning backend.",
            "Cross-origin restrictions, CSP, service workers, authentication and server-side features may prevent offline operation.",
            "CSS url() and @import rewriting is best-effort; inspect the report and test in a disconnected browser."
        ]
    }
    (p / "offline-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    # Keep the conventional preview/download entry point at project root, with paths still relative.
    (p / "offline.html").write_text(str(soup), encoding="utf-8")
    return report



def _as_data_uri(path: Path):
    if not path.is_file() or path.stat().st_size == 0:
        return None
    mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    return "data:" + mime + ";base64," + base64.b64encode(path.read_bytes()).decode("ascii")


def build_single_file(pid: str):
    """Create a self-contained HTML file by inlining captured CSS, JS and binary assets."""
    p = project_dir(pid)
    m = read_manifest(p)
    base_url = m.get("final_url") or m.get("url") or ""
    mapping = url_to_file_map(m, p)
    html_path = p / "offline" / "offline.html"
    if not html_path.is_file():
        build_offline(pid)
    soup = BeautifulSoup(html_path.read_text("utf-8", errors="replace"), "html.parser")
    by_local = {}
    for rec in m.get("resources", []):
        if _valid_resource_record(p, rec):
            by_local[rec.get("file", "").replace("\\", "/")] = p / rec["file"]

    # Resolve local references relative to the offline document.
    def local_path(value):
        if not value or value.startswith(("data:", "blob:", "javascript:", "#", "http://", "https://")):
            return None
        candidate = (p / "offline" / value).resolve()
        if p.resolve() not in candidate.parents or not candidate.is_file() or candidate.stat().st_size == 0:
            candidate = (p / value).resolve()
        if p.resolve() not in candidate.parents or not candidate.is_file() or candidate.stat().st_size == 0:
            return None
        return candidate

    embedded = {"scripts": 0, "stylesheets": 0, "images": 0, "other_assets": 0, "unembedded": []}

    for tag in list(soup.find_all("link", href=True)):
        rel = [str(x).lower() for x in (tag.get("rel") or [])]
        if "stylesheet" not in rel:
            continue
        f = local_path(tag.get("href"))
        if f:
            css = f.read_text("utf-8", errors="replace")
            # Inline CSS URLs as data URIs.
            def css_url(match):
                raw = match.group(2).strip().strip("\"'")
                asset = local_path(raw)
                if not asset:
                    embedded["unembedded"].append(raw)
                    return match.group(0)
                uri = _as_data_uri(asset)
                if uri:
                    embedded["other_assets"] += 1
                    q = match.group(1) or ""
                    return "url(" + q + uri + q + ")"
                return match.group(0)
            css = re.sub(r"url\(\s*([\"']?)(.*?)\1\s*\)", css_url, css, flags=re.I)
            style = soup.new_tag("style")
            style.string = css
            tag.replace_with(style)
            embedded["stylesheets"] += 1
        else:
            embedded["unembedded"].append(tag.get("href"))

    for tag in list(soup.find_all("script", src=True)):
        f = local_path(tag.get("src"))
        if f:
            script = soup.new_tag("script")
            script.string = f.read_text("utf-8", errors="replace")
            for attr in ("type", "async", "defer", "nomodule"):
                if attr in tag.attrs:
                    script[attr] = tag.attrs[attr]
            tag.replace_with(script)
            embedded["scripts"] += 1
        else:
            embedded["unembedded"].append(tag.get("src"))

    for tag_name, attr in (("img", "src"), ("source", "src"), ("video", "poster"),
                           ("audio", "src"), ("input", "src")):
        for tag in soup.find_all(tag_name):
            value = tag.get(attr)
            f = local_path(value)
            if f:
                uri = _as_data_uri(f)
                if uri:
                    tag[attr] = uri
                    embedded["images"] += 1
            elif value and not value.startswith(("data:", "blob:", "http://", "https://")):
                embedded["unembedded"].append(value)

    for tag in soup.find_all(style=True):
        style = tag.get("style", "")
        def inline_css_url(match):
            raw = match.group(2).strip().strip("\"'")
            f = local_path(raw)
            if not f:
                return match.group(0)
            uri = _as_data_uri(f)
            q = match.group(1) or ""
            return "url(" + q + uri + q + ")" if uri else match.group(0)
        tag["style"] = re.sub(r"url\(\s*([\"']?)(.*?)\1\s*\)", inline_css_url, style, flags=re.I)

    output = p / "single-file.html"
    output.write_text("<!doctype html>\n" + str(soup), encoding="utf-8")
    report = {
        "project": pid, "format": "single-file-html", "output": output.name,
        "embedded": embedded,
        "single_file_ready": len(embedded["unembedded"]) == 0
    }
    (p / "single-file-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report, output


@app.post("/api/projects/{pid}/patch")
async def patch(pid: str):
    return build_offline(pid)


@app.get("/api/projects/{pid}/single-file")
async def single_file_download(pid: str):
    report, output = build_single_file(pid)
    return FileResponse(output, filename=f"jWebDebugger-{pid}-single-file.html", media_type="text/html")

@app.get("/api/projects/{pid}/single-file-report")
async def single_file_report(pid: str):
    report, _ = build_single_file(pid)
    return report


@app.post("/api/projects/{pid}/fidelity-test")
async def offline_fidelity_test(pid: str):
    """Compare the captured live/original URL with the generated offline page."""
    p = project_dir(pid)
    manifest = read_manifest(p)
    offline_file = p / "offline" / "offline.html"
    if not offline_file.is_file():
        build_offline(pid)
    original_url = manifest.get("final_url") or manifest.get("url")
    if not original_url:
        raise HTTPException(400, "This project has no original URL to compare.")
    host = str(CONFIG.get("server", {}).get("host", "127.0.0.1"))
    port = int(CONFIG.get("server", {}).get("port", 8765))
    # Browser must reach the app through loopback even when the UI is bound to 0.0.0.0.
    offline_url = f"http://127.0.0.1:{port}/api/projects/{pid}/preview"
    out_dir = p / "fidelity-test"
    out_dir.mkdir(exist_ok=True)
    results = {}
    async with async_playwright() as pw:
        try:
            browser = await pw.chromium.launch(headless=True)
        except Exception as exc:
            raise HTTPException(503, "Chromium is unavailable. Check that the bundled Playwright browser is installed in the application folder, then restart jWebDebugger. Details: " + str(exc)[:500])
        for label, target_url in (("original", original_url), ("offline", offline_url)):
            page_errors, failed_requests, bad_responses = [], [], []
            context = await browser.new_context(viewport={"width": 1365, "height": 900},
                                                device_scale_factor=1, ignore_https_errors=False)
            page = await context.new_page()
            page.on("pageerror", lambda exc, bucket=page_errors: bucket.append(str(exc)))
            page.on("requestfailed", lambda req, bucket=failed_requests: bucket.append({
                "url": req.url, "error": req.failure
            }))
            page.on("response", lambda resp, bucket=bad_responses: bucket.append({
                "url": resp.url, "status": resp.status
            }) if resp.status >= 400 else None)
            nav_error = None
            try:
                await page.goto(target_url, wait_until="domcontentloaded", timeout=45000)
                try:
                    await page.wait_for_load_state("networkidle", timeout=9000)
                except Exception:
                    pass
                await page.wait_for_timeout(1800)
                metrics = await page.evaluate("""() => {
                  const norm = s => (s || '').replace(/\\\\s+/g,' ').trim();
                  const text = norm(document.body ? document.body.innerText : '');
                  const imgs = [...document.images];
                  const links = [...document.querySelectorAll('a[href]')];
                  return {
                    title: document.title || '',
                    text: text.slice(0,120000),
                    text_length: text.length,
                    headings: [...document.querySelectorAll('h1,h2,h3')].map(x=>norm(x.innerText)).filter(Boolean).slice(0,100),
                    image_count: imgs.length,
                    images_loaded: imgs.filter(x=>x.complete && x.naturalWidth>0).length,
                    stylesheet_count: [...document.styleSheets].length,
                    script_count: document.scripts.length,
                    link_count: links.length,
                    viewport: {width: innerWidth,height: innerHeight},
                    page_size: {width: document.documentElement.scrollWidth,height: document.documentElement.scrollHeight}
                  };
                }""")
                await page.screenshot(path=str(out_dir / f"{label}.png"), full_page=False)
            except Exception as exc:
                nav_error = str(exc)
                metrics = {"title": "", "text": "", "text_length": 0,
                           "headings": [], "image_count": 0, "images_loaded": 0,
                           "stylesheet_count": 0, "script_count": 0, "link_count": 0}
            results[label] = {"url": target_url, "metrics": metrics,
                              "navigation_error": nav_error,
                              "page_errors": page_errors[:100],
                              "failed_requests": failed_requests[:150],
                              "http_errors": bad_responses[:150]}
            await context.close()
        await browser.close()

    a, b = results["original"]["metrics"], results["offline"]["metrics"]
    import difflib
    ta, tb = a.get("text", ""), b.get("text", "")
    text_similarity = round(difflib.SequenceMatcher(None, ta[:50000], tb[:50000]).ratio() * 100, 1)
    image_load_rate = round((b.get("images_loaded", 0) / max(1, b.get("image_count", 0))) * 100, 1)
    try:
        from PIL import Image, ImageChops, ImageStat
        ia = Image.open(out_dir / "original.png").convert("RGB")
        ib = Image.open(out_dir / "offline.png").convert("RGB")
        if ia.size != ib.size:
            ib = ib.resize(ia.size)
        diff = ImageChops.difference(ia, ib)
        mean_diff = sum(ImageStat.Stat(diff).mean) / 3
        visual_similarity = round(max(0, 100 * (1 - mean_diff / 255)), 1)
        diff.save(out_dir / "visual-difference.png")
    except Exception:
        visual_similarity = None
    report = {
        "project_id": pid, "tested_at": datetime.now(timezone.utc).isoformat(),
        "overall": "PASS" if not results["offline"]["navigation_error"]
                    and not results["offline"]["failed_requests"]
                    and not results["offline"]["http_errors"] else "REVIEW",
        "scores": {"text_similarity_percent": text_similarity,
                   "visual_similarity_estimate_percent": visual_similarity,
                   "offline_image_load_percent": image_load_rate},
        "comparison": {
            "title_match": a.get("title") == b.get("title"),
            "original": {k:v for k,v in a.items() if k != "text"},
            "offline": {k:v for k,v in b.items() if k != "text"}
        },
        "runtime": results,
        "screenshots": ["fidelity-test/original.png", "fidelity-test/offline.png",
                        "fidelity-test/visual-difference.png"],
        "interpretation": [
            "Visual similarity is a screenshot-based estimate, not a pixel-perfect or semantic pass/fail score.",
            "The live page and offline page may differ because of time, personalization, cookies, authentication, ads or dynamic data.",
            "A clean offline load does not prove that forms, login, APIs, maps, payments or server-side actions work offline.",
            "Use the offline HTTP errors, failed requests, page errors and image-load rate to identify missing dependencies."
        ]
    }
    (out_dir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


@app.get("/api/projects/{pid}/preview")
async def preview(pid: str):
    p = project_dir(pid)
    f = p / "offline.html"
    if not f.exists():
        build_offline(pid)
    return FileResponse(f, media_type="text/html")

@app.get("/api/projects/{pid}/download")
async def download(pid: str):
    p = project_dir(pid)
    if not (p / "offline.html").exists():
        build_offline(pid)
    target = DATA / f"{pid}-offline-package.zip"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as z:
        for f in p.rglob("*"):
            if f.is_file():
                z.write(f, f.relative_to(p))
    return FileResponse(target, filename=f"jWebDebugger-{pid}.zip", media_type="application/zip")


@app.get("/api/projects/{pid}/site/{file_path:path}")
async def project_site_file(pid: str, file_path: str):
    p = project_dir(pid)
    manifest = read_manifest(p)
    rel = file_path.replace("\\", "/").lstrip("/")
    if ".." in Path(rel).parts:
        raise HTTPException(400, "Invalid path")
    if rel == (manifest.get("index_file") or "index.html"):
        target = p / "original.html"
        media = "text/html"
    else:
        target = (p / rel).resolve()
        media = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
    if p.resolve() not in target.resolve().parents or not target.is_file():
        raise HTTPException(404, "Local site file not found")
    return FileResponse(target, media_type=media)

@app.post("/api/projects/{pid}/capture-dependencies")
async def recapture_project_dependencies(pid: str):
    result = await capture_project_dependencies(pid, wait_seconds=5.0)
    return result

@app.get("/api/projects/{pid}/resource/{filename}")
async def resource(pid: str, filename: str):
    p = project_dir(pid)
    f = (p / "resources" / filename).resolve()
    if p.resolve() not in f.parents or not f.is_file():
        raise HTTPException(404, "Resource not found")
    return FileResponse(f)


@app.get("/api/projects/{pid}/{file_path:path}")
async def project_file(pid: str, file_path: str):
    p = project_dir(pid)
    target = (p / file_path).resolve()