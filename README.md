# jWebDebugger Studio — v1.6.1

A local-first website capture and diagnostics tool. The Python backend is the v1.6.1 source snapshot; the browser interface in `static/index.html` has been reconstructed to expose the backend's documented API workflows.

## Features

- Capture an HTTP/HTTPS website using headless Chromium.
- Import a local HTML website and its related files.
- Browse saved projects and inspect the capture manifest.
- Review HTTP response errors, failed requests and browser console errors.
- Build and preview an offline copy.
- Run the original/offline fidelity comparison.
- Download a project as a ZIP package.
- View service health and reload application configuration.

The reconstructed interface is a functional replacement, not a recovery of the original missing frontend source. Review the UI and test it against your target sites before relying on it for production work.

## Requirements

- Python 3.10+
- Chromium installed through Playwright

## Installation

```bash
python -m venv .venv
# Windows:
.venv\\Scripts\\activate
# macOS/Linux:
source .venv/bin/activate

python -m pip install -r requirements.txt
python -m playwright install chromium
```

## Run

From the repository root:

```bash
uvicorn app:app --host 127.0.0.1 --port 8765
```

Open http://127.0.0.1:8765 in your browser.

## Data and configuration

- Project data is stored in the local `projects/` directory.
- `config.json` is created with defaults on first launch.
- The interface binds to the local service; do not expose it to an untrusted network without adding authentication and appropriate security controls.

## Notes

- Website capture should be limited to sites you are authorized to inspect.
- Browser-side diagnostics cannot prove server-side root cause. Correlate findings with authorized server logs.
- Some sites depend on authentication, dynamic API calls, service workers, CSP, or cross-origin resources that cannot be fully reproduced offline.
- The local import workflow has a 100 MB request limit in the backend.
