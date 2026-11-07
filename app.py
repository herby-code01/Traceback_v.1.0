"""Traceback control plane (Flask). Holds the inference key; never ships it to the sandbox."""
import io
import json
import os
import tempfile
import threading
import time
import uuid

from flask import Flask, jsonify, request, send_from_directory, abort, Response

from traceback_core import fixtures, llm
from traceback_core.investigator import Timeline, investigate, run_containment
from traceback_core.sandbox import Sandbox, pick_driver
from traceback_core.snapshot import SnapshotError, as_text, load_zip

app = Flask(__name__, static_folder="static", static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = 60 * 1024 * 1024
JOBS = {}
LOCK = threading.Lock()
MAX_JOBS = 50


def _new_job(kind):
    jid = uuid.uuid4().hex[:12]
    tl = Timeline()
    job = {"id": jid, "kind": kind, "status": "running", "created": time.time(), "events": tl.events, "tl": tl,
           "trees": {}, "report": None, "error": None}
    with LOCK:
        if len(JOBS) >= MAX_JOBS:
            JOBS.pop(min(JOBS, key=lambda k: JOBS[k]["created"]))
        JOBS[jid] = job
    return job


def _run_investigation(job, before, after, question, log):
    job["trees"] = {"before": before, "after": after}
    try:
        job["report"] = investigate(before, after, question, log, Sandbox(), job["tl"])
        job["report"]["id"] = job["id"]
        job["status"] = "done"
    except Exception as e:  # surface, never hang the UI
        job["error"] = f"{type(e).__name__}: {e}"
        job["status"] = "error"


def _run_containment(job):
    try:
        job["report"] = run_containment(Sandbox())
        job["report"]["id"] = job["id"]
        job["status"] = "done"
    except Exception as e:
        job["error"] = f"{type(e).__name__}: {e}"
        job["status"] = "error"


@app.get("/")
def index():
    return send_from_directory("static", "index.html")


@app.get("/api/health")
def health():
    return jsonify(ok=True, driver=pick_driver(), model_enabled=llm.enabled(),
                   model=llm.model_name() if llm.enabled() else None)


@app.post("/api/runs")
def create_run():
    try:
        before = load_zip(request.files["before"])
        after = load_zip(request.files["after"])
    except KeyError:
        return jsonify(error="Upload both a 'before' and an 'after' ZIP."), 400
    except SnapshotError as e:
        return jsonify(error=str(e)), 400
    log = ""
    if "log" in request.files:
        log = (as_text(request.files["log"].read(256 * 1024)) or "")
    question = (request.form.get("question") or "Why does it fail now?")[:500]
    job = _new_job("investigation")
    threading.Thread(target=_run_investigation, args=(job, before, after, question, log), daemon=True).start()
    return jsonify(id=job["id"]), 202


@app.post("/api/demo/<name>")
def demo(name):
    if name == "containment":
        job = _new_job("containment")
        threading.Thread(target=_run_containment, args=(job,), daemon=True).start()
        return jsonify(id=job["id"]), 202
    if name not in fixtures.FIXTURES:
        abort(404)
    before, after = fixtures.FIXTURES[name]()
    q = "The app worked yesterday. Why does it fail now?"
    job = _new_job("investigation")
    threading.Thread(target=_run_investigation, args=(job, before, after, q, ""), daemon=True).start()
    return jsonify(id=job["id"]), 202


@app.get("/api/runs/<jid>")
def get_run(jid):
    job = JOBS.get(jid) or abort(404)
    return jsonify(id=jid, kind=job["kind"], status=job["status"], error=job["error"],
                   events=list(job["events"]), report=job["report"])


@app.get("/api/runs/<jid>/file")
def get_file(jid):
    """Evidence viewer. Only serves paths that exist in the in-memory snapshot — no filesystem access."""
    job = JOBS.get(jid) or abort(404)
    tree = job["trees"].get(request.args.get("side", "after")) or abort(404)
    data = tree.get(request.args.get("path", ""))
    if data is None:
        abort(404)
    text = as_text(data)
    if text is None:
        return jsonify(binary=True, lines=[])
    return jsonify(binary=False, lines=text.splitlines()[:2000])


@app.get("/api/runs/<jid>/patch.diff")
def get_patch(jid):
    """Download only. Traceback never applies the patch."""
    job = JOBS.get(jid) or abort(404)
    patch = ((job["report"] or {}).get("finding") or {}).get("patch")
    if not patch:
        abort(404)
    return Response(patch, mimetype="text/x-diff", headers={"Content-Disposition": "attachment; filename=traceback-fix.diff"})


@app.get("/api/fixtures/<name>/<side>.zip")
def fixture_zip(name, side):
    if name not in fixtures.FIXTURES or side not in ("before", "after"):
        abort(404)
    import zipfile
    tree = fixtures.FIXTURES[name]()[0 if side == "before" else 1]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for p, d in tree.items():
            z.writestr(f"orbit/{p}", d)
    return Response(buf.getvalue(), mimetype="application/zip",
                    headers={"Content-Disposition": f"attachment; filename={name}-{side}.zip"})


if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8080")), threaded=True)
