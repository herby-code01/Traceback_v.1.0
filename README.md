# Traceback

**When software breaks, reconstruct the why.** Give it two project snapshots (before: worked, after: broken) and a plain-language question. Traceback compares them, replays targeted checks in disposable sandboxes, and returns an evidence-linked cause, a confidence level, and a patch for a human to review.

Built for the Vultr Agent Rush hackathon, Challenge 1: **Blast Radius Zero** (run untrusted code safely, show the containment).

## How it works

```
 two ZIPs ──► COMPARE ──► REPLAY ──► CONNECT ──► PROVE
              hashes,     before +    undo each    cause, confidence,
              diffs,      after in    suspect      source lines, log line,
              config &    fresh       alone and    replay result, patch
              dep changes sandboxes   replay it    (never auto-applied)
```

The core idea is **counterfactual replay**. Text analysis only *ranks* suspects. A hypothesis is "confirmed" only when undoing that single change makes the checks pass in a fresh sandbox. If nothing passes, or the *before* snapshot also fails, Traceback says **inconclusive** instead of guessing.

**The model guides; deterministic tools gather evidence.** Vultr Serverless Inference (optional) (1) orders which suspects to replay first and (2) writes the plain-English explanation from already-verified evidence. It cannot invent evidence: triage output is filtered to candidate ids the diff produced, and the verdict comes from replay results. Project files are treated as untrusted prompt content. With no API key everything falls back to deterministic behaviour (the UI shows which was used).

## Trust boundary

| Layer | What it does |
|---|---|
| Worker env | Fresh workspace per run, scrubbed env (no keys), destroyed in `finally`; teardown is recorded in the report |
| OS isolation | **docker driver (production):** `--network none`, read-only rootfs, `--cap-drop ALL`, `no-new-privileges`, uid 1000, pids/mem/cpu limits, tmpfs `/tmp`. **ns driver (dev fallback):** `unshare -Urn` user+network namespaces |
| In-worker guard | rlimits (CPU, memory, file size, fds) and a Python audit hook that blocks **and logs** reads/writes outside the workspace, network calls, subprocesses, ctypes |
| Control plane | Holds the inference key; patch is returned as text/download only |

Honest limits: the audit hook is evidence + defence in depth, not a hard boundary (native code can bypass it), so the OS layer is what you rely on. The ns driver has no filesystem namespace, so outside-workspace *reads* are stopped only by the audit hook. Use the docker driver in production. Checks must be `python <script>` in this version.

## Run it locally

```bash
pip install -r requirements.txt   # flask (+ gunicorn for deploy)
python app.py                     # http://127.0.0.1:8080
python -m unittest discover -s tests -v
```

Click **Known cause**, **Inconclusive**, or **Containment demo**, or upload your own two ZIPs (sample ZIPs are linked in the UI; `python -m traceback_core.fixtures fixtures/` writes them to disk).

Declare checks in `traceback.json` at the snapshot root:

```json
{"checks": [{"name": "startup check", "cmd": ["python", "startup_check.py"]}]}
```

With none, Traceback uses `startup_check.py` / `check.py` if present, else a compile check of every `.py` file.

## Deploy on Vultr

1. Create a **Cloud Compute** instance (Ubuntu 24.04, 2 vCPU / 4 GB is plenty).
2. Get a **Serverless Inference** API key from the Vultr customer portal, then run `deploy/list_models.sh` and pick a model id.
3. On the instance, as root:
   ```bash
   git clone <your repo> && cd traceback
   DOMAIN=traceback.example.com VULTR_INFERENCE_API_KEY=... VULTR_INFERENCE_MODEL=<model-id> bash deploy/setup.sh
   curl -s localhost:8080/api/health   # expect "driver":"docker"
   ```
   Omit `DOMAIN` to serve plain HTTP on :80.
4. Open the URL, run **Containment demo**, confirm the chip says `sandbox: docker`.

## Demo script (≈2 minutes)

1. "The app worked yesterday." Load **Known cause** → watch compare → replay → undo-each-suspect. Only the env-var rename passes; the unrelated edits don't.
2. Click the source link: `.env.example` line 4, highlighted. Show the one-line patch marked *not applied*.
3. **Containment demo**: a hostile script reads `/etc/passwd`, a control-plane canary secret, writes outside its workspace, calls out, spawns a shell. All blocked and logged; canary unchanged and unleaked; sandbox destroyed and a fresh one starts.
4. **Inconclusive**: a failure that also happens before the change. Traceback refuses to blame the diff.

## Layout

```
app.py                      Flask API + static UI
static/index.html           upload, timeline, evidence viewer, patch, sandbox panel
traceback_core/
  snapshot.py               safe ZIP loading (no zip-slip, size caps) + diffing
  evidence.py               config / dependency / failure-line extraction
  investigator.py           pipeline, counterfactual replay, containment demo
  sandbox.py  guard.py      docker + ns drivers, in-worker guard
  llm.py                    Vultr Serverless Inference client (stdlib)
  fixtures.py               bundled cases
deploy/                     setup.sh, systemd unit, model lister
tests/test_e2e.py           acceptance checks
```

## Known gaps / next steps

- Config and dependency undo is line-based (env, ini, yaml, toml, json, requirements, package.json); other change types fall back to whole-file revert and are flagged as broader than the real defect.
- Python-only checks; Node/other runtimes need a generalised guard.
- Jobs are in memory (last 50); no auth or rate limiting. Add both before exposing publicly.
- A one-VM-per-run `VultrDriver` (Vultr API) is the natural stronger-isolation extension.
