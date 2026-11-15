# jWebDebugger Studio — source snapshot (v1.6.1)

This repository contains the latest available Python backend source snapshot from the project Library.

## Important: incomplete project snapshot

The backend expects a `static/index.html` frontend directory. That frontend asset was not present among the located jWebDebugger project files, so this upload is **not yet a complete runnable application**. The UI cannot be served until the matching frontend is added. No unrelated HTML file has been substituted.

## Backend dependencies

- fastapi
- uvicorn[standard]
- pydantic
- beautifulsoup4
- playwright
- pillow (optional; used for image-based fidelity scoring)

Install dependencies with:

```bash
python -m pip install -r requirements.txt
python -m playwright install chromium
```

Run after adding the matching `static/index.html`:

```bash
uvicorn app:app --host 127.0.0.1 --port 8765
```

Project data is written to the local `projects/` directory. Review the source and configure network access appropriately before use.
