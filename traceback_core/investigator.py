"""The investigation pipeline: compare -> replay -> connect -> prove.

Method: counterfactual replay. For each suspect change we build a patched copy of the AFTER snapshot
that undoes only that change, rerun the same checks in a fresh sandbox, and see whether it passes.
A hypothesis is "confirmed" only by an observed pass; text analysis only ranks what to test first.
"""
import difflib
import os
import re
import secrets
import time

from . import evidence as ev
from . import llm
from .sandbox import Sandbox
from .snapshot import as_text, diff_trees

DOC_EXT = {".md", ".rst", ".txt"}
COMPILE_CHECK = '''"""Fallback check injected by Traceback when the project declares none: every .py file must compile."""
import pathlib, sys
bad = 0
for p in sorted(pathlib.Path(".").rglob("*.py")):
    if ".traceback" in p.parts:
        continue
    try:
        compile(p.read_text(), str(p), "exec")
    except SyntaxError as e:
        print(f"SyntaxError in {p}:{e.lineno}: {e.msg}", file=sys.stderr)
        bad += 1
print("compile check:", "FAILED" if bad else "ok")
sys.exit(1 if bad else 0)
'''
MAX_COUNTERFACTUALS = 6


class Timeline:
    def __init__(self):
        self.events = []

    def add(self, kind, label, detail="", ref=None):
        self.events.append({"t": time.strftime("%H:%M:%S"), "ts": time.time(), "kind": kind, "label": label,
                            "detail": detail, "ref": ref})


def discover_checks(after, before):
    import json
    for tree in (after, before):
        raw = tree.get("traceback.json")
        if raw:
            try:
                checks = json.loads(raw.decode())["checks"]
                if checks and all("name" in c and "cmd" in c for c in checks):
                    return checks, "traceback.json"
            except Exception:
                pass
    for name in ("startup_check.py", "check.py"):
        if name in after or name in before:
            return [{"name": "startup check", "cmd": ["python", name]}], f"auto-detected {name}"
    return [{"name": "compile check", "cmd": ["python", ".traceback/compile_check.py"]}], "fallback: compile every .py file"


def _lines(data):
    return as_text(data).splitlines(keepends=True)


def _set_line(text, line_no, new):
    lines = text.splitlines(keepends=True)
    if not 1 <= line_no <= len(lines):
        return None
    nl = "\n" if lines[line_no - 1].endswith("\n") else ""
    lines[line_no - 1] = new.rstrip("\n") + nl
    return "".join(lines)


def _insert_line(text, line_no, new):
    lines = text.splitlines(keepends=True)
    idx = min(max(line_no - 1, 0), len(lines))
    if lines and not lines[-1].endswith("\n") and idx == len(lines):
        lines[-1] += "\n"
    lines.insert(idx, new.rstrip("\n") + "\n")
    return "".join(lines)


def _delete_line(text, line_no):
    lines = text.splitlines(keepends=True)
    if not 1 <= line_no <= len(lines):
        return None
    del lines[line_no - 1]
    return "".join(lines)


def build_candidates(before, after, diff, cfg, deps):
    cands = []

    def add(**k):
        k["id"] = f"c{len(cands) + 1}"
        cands.append(k)

    for c in cfg:
        if c["kind"] == "renamed":
            title = f"Config key renamed: {c['key']} → {c['new_key']}"
        elif c["kind"] == "removed":
            title = f"Config key removed: {c['key']}"
        elif c["kind"] == "added":
            title = f"Config key added: {c['key']}"
        else:
            title = f"Config value changed: {c['key']}"
        add(type="config", title=title, path=c["path"], line=c["line_after"] or c["line_before"], change=c,
            keys=[c["key"]] + ([c["new_key"]] if c.get("new_key") else []))
    for d in deps:
        add(type="dependency", title=f"Dependency {d['kind']}: {d['package']} {d['old'] or '—'} → {d['new'] or '—'}",
            path=d["path"], line=d["line_after"] or d["line_before"], change=d, keys=[d["package"]])
    cfg_paths = {c["path"] for c in cfg} | {d["path"] for d in deps}
    for m in diff["modified"]:
        if m["path"] in cfg_paths or os.path.splitext(m["path"])[1] in DOC_EXT or not m["text"]:
            continue
        first = (m.get("changed_after_lines") or [(None, None)])[0][0]
        add(type="file", title=f"File modified: {m['path']}", path=m["path"], line=first, change={"kind": "modified"}, keys=[])
    for p in diff["removed"]:
        if os.path.splitext(p)[1] not in DOC_EXT:
            add(type="file", title=f"File removed: {p}", path=p, line=None, change={"kind": "removed"}, keys=[])
    for p in diff["added"]:
        if os.path.splitext(p)[1] not in DOC_EXT and not p.startswith(".traceback/"):
            add(type="file", title=f"File added: {p}", path=p, line=None, change={"kind": "added"}, keys=[])
    return cands


def revert(cand, before, after):
    """Return a copy of `after` with only this candidate's change undone, or None if not expressible."""
    files = dict(after)
    ch, path = cand["change"], cand["path"]
    if cand["type"] == "file":
        if ch["kind"] == "added":
            files.pop(path, None)
        else:
            files[path] = before[path]
        return files
    text = as_text(after[path]) if path in after else ""
    k = ch["kind"]
    if k in ("renamed", "changed") and ch["after_line_text"] is not None and ch["before_line_text"] is not None:
        new = _set_line(text, ch["line_after"], ch["before_line_text"])
    elif k == "removed":
        new = _insert_line(text, ch["line_before"], ch["before_line_text"])
    elif k == "added":
        new = _delete_line(text, ch["line_after"])
    else:
        new = None
    if new is None:
        return None
    files[path] = new.encode()
    return files


def score(cand, failure_text, frames):
    s, why = 1, ["changed between snapshots"]
    for k in cand["keys"]:
        if k and re.search(r"(?<![\w])" + re.escape(k) + r"(?![\w])", failure_text, re.I):
            s += 4
            why.append(f"“{k}” appears in the failure output")
            break
    base = os.path.basename(cand["path"] or "")
    if cand["type"] == "file":
        for f, ln in frames:
            if f == cand["path"] or f.endswith("/" + cand["path"]) or os.path.basename(f) == base:
                s += 3
                why.append(f"{cand['path']}:{ln} is in the failing traceback")
                break
    elif base and base in failure_text:
        s += 1
        why.append(f"{base} is named in the failure output")
    return s, why


def run_diff_patch(from_text, to_text, path):
    """Unified diff that turns the current (broken) file into the fixed one."""
    return "".join(l if l.endswith("\n") else l + "\n" for l in difflib.unified_diff(
        from_text.splitlines(), to_text.splitlines(), f"a/{path}", f"b/{path}", lineterm="", n=2))


def combined_output(replay):
    out = []
    for r in replay["results"]:
        out += [r["stdout"], r["stderr"]]
    return "\n".join(o for o in out if o)


def excerpt_ref(replay, label, needle=None):
    """Find (check, line_no, text) of the most relevant output line in a replay."""
    for r in replay["results"]:
        lines = (r["stdout"] + "\n" + r["stderr"]).splitlines()
        hits = ev.error_lines("\n".join(lines))
        if needle:
            hits = [h for h in hits if needle.lower() in h[1].lower()] or hits
        if hits:
            n, t = hits[-1]
            return {"kind": "check_output", "replay": label, "check": r["name"], "line": n, "text": t}
    return None


def investigate(before, after, question, extra_log, sandbox=None, tl=None):
    sandbox = sandbox or Sandbox()
    tl = tl or Timeline()
    report = {"question": question, "events": tl.events}
    diff = diff_trees(before, after)
    cfg = ev.config_changes(before, after, as_text)
    deps = ev.dependency_changes(before, after, as_text)
    report["summary"] = {"files_before": len(before), "files_after": len(after), "added": diff["added"], "removed": diff["removed"],
                         "modified": [m["path"] for m in diff["modified"]], "unchanged": diff["unchanged"],
                         "config_changes": len(cfg), "dependency_changes": len(deps)}
    report["diff"] = [{"path": m["path"], "unified": m.get("unified", "")} for m in diff["modified"]]
    tl.add("compare", f"Compared snapshots: {len(diff['modified'])} modified, {len(diff['added'])} added, {len(diff['removed'])} removed",
           f"{len(cfg)} config change(s), {len(deps)} dependency change(s)")
    for c in cfg:
        tl.add("change", f"Config {c['kind']}: " + (f"{c['key']} → {c['new_key']}" if c["kind"] == "renamed" else c["key"]),
               f"{c['path']}:{c['line_after'] or c['line_before']}",
               {"side": "after" if c["line_after"] else "before", "path": c["path"], "line": c["line_after"] or c["line_before"]})

    checks, how = discover_checks(after, before)
    injected = {".traceback/compile_check.py": COMPILE_CHECK.encode()} if "compile_check" in checks[0]["cmd"][-1] else {}
    report["checks"] = {"list": checks, "source": how}
    tl.add("plan", f"Selected {len(checks)} check(s) to replay", how)

    # --- replay before / after ------------------------------------------------
    replays = []

    def replay(files, label):
        r = sandbox.run({**files, **injected}, checks, label)
        replays.append(r)
        return r
    base = replay(before, "before")
    tl.add("replay", f"Before snapshot: {'passes' if base['passed'] else 'FAILS'}", f"{base['driver']} sandbox · destroyed: {base['teardown']['workspace_removed']}")
    fail = replay(after, "after")
    tl.add("replay", f"After snapshot: {'passes' if fail['passed'] else 'FAILS'}", f"{fail['driver']} sandbox · destroyed: {fail['teardown']['workspace_removed']}",
           excerpt_ref(fail, "after"))
    fail_text = combined_output(fail) + "\n" + (extra_log or "")
    frames = ev.traceback_frames(fail_text)
    report["replays"] = {"before": slim(base), "after": slim(fail), "counterfactual": []}

    # --- candidates -----------------------------------------------------------
    cands = build_candidates(before, after, diff, cfg, deps)
    for c in cands:
        c["score"], c["why"] = score(c, fail_text, frames)
        c["tested"], c["passed"] = False, None
    cands.sort(key=lambda c: -c["score"])
    model = {"used": False, "provider": "Vultr Serverless Inference" if llm.enabled() else None, "notes": []}
    report["model"] = model

    verdict, finding = None, None
    if base["passed"] and not fail["passed"] and cands:
        if llm.enabled():
            order, err = llm.triage(question, "\n".join(t for _, t in ev.error_lines(fail_text)) or fail_text[-800:], cands)
            if order:
                model["used"] = True
                pos = {i: n for n, i in enumerate(order)}
                cands.sort(key=lambda c: (-c["score"], pos.get(c["id"], 99)))
                tl.add("model", "Model triaged suspects", "Order: " + " > ".join(order[:4]))
            else:
                model["notes"].append("triage skipped: " + str(err))
                tl.add("model", "Model triage unavailable — using deterministic ranking", str(err))
        # --- counterfactual replays ------------------------------------------
        confirmed = []
        for c in cands[:MAX_COUNTERFACTUALS]:
            patched = revert(c, before, after)
            if patched is None:
                c["tested"], c["passed"] = False, None
                continue
            r = replay(patched, f"undo {c['id']}")
            c["tested"], c["passed"] = True, r["passed"]
            report["replays"]["counterfactual"].append({"candidate": c["id"], **slim(r)})
            tl.add("replay", f"Undo “{c['title']}” → {'PASSES' if r['passed'] else 'still fails'}", f"{r['driver']} sandbox · destroyed: {r['teardown']['workspace_removed']}")
            if r["passed"]:
                confirmed.append((c, patched))
                if len(confirmed) >= 2:
                    break
        if confirmed:
            verdict = "confirmed"
            top, patched = confirmed[0]
            finding = build_finding(top, patched, before, after, fail, report, question, confirmed, model, tl)
        else:
            verdict = "inconclusive"
            finding = {"title": "No single change explains the failure", "confidence": "low",
                       "explanation": "The after snapshot fails, but undoing each suspect change on its own did not make the checks pass. "
                                      "The cause may be a combination of changes, something outside the snapshot, or a check that needs more input.",
                       "explanation_source": "deterministic", "evidence": failure_evidence(fail), "patch": None,
                       "alternatives": [{"id": c["id"], "title": c["title"], "score": c["score"]} for c in cands[:3]],
                       "caveats": ["Add logs or a more specific check in traceback.json and rerun."]}
    elif not fail["passed"] and not base["passed"]:
        verdict = "inconclusive"
        finding = {"title": "The before snapshot also fails", "confidence": "low",
                   "explanation": "Both snapshots fail the same checks, so the failure cannot be attributed to the changes between them.",
                   "explanation_source": "deterministic", "evidence": failure_evidence(base) + failure_evidence(fail), "patch": None,
                   "alternatives": [], "caveats": ["Provide a before snapshot that actually worked, or a check that distinguishes the two."]}
    elif fail["passed"]:
        verdict = "no_failure_reproduced"
        finding = {"title": "The after snapshot passes these checks", "confidence": "n/a",
                   "explanation": "The failure was not reproduced by the selected checks. The breakage may need a different check, input, or environment.",
                   "explanation_source": "deterministic", "evidence": [], "patch": None, "alternatives": [],
                   "caveats": ["Add the failing command to traceback.json."]}
    else:
        verdict = "inconclusive"
        finding = {"title": "Snapshots are identical in every file Traceback compares", "confidence": "low",
                   "explanation": "There are no differences to explain the failure.", "explanation_source": "deterministic",
                   "evidence": failure_evidence(fail), "patch": None, "alternatives": [], "caveats": []}

    tl.add("verdict", f"Verdict: {verdict.replace('_', ' ')}", finding["title"])
    report.update(verdict=verdict, finding=finding, candidates=[{k: v for k, v in c.items() if k not in ("change",)} for c in cands])
    report["sandbox"] = {"driver": sandbox.driver, "limits": replays[0]["limits"], "runs": len(replays),
                         "all_workspaces_destroyed": all(r["teardown"]["workspace_removed"] for r in replays),
                         "violations_total": sum(len(x["violations"]) for r in replays for x in r["results"])}
    return report


def slim(r):
    return {"label": r["label"], "driver": r["driver"], "passed": r["passed"], "duration_s": r["duration_s"], "teardown": r["teardown"],
            "results": [{k: x[k] for k in ("name", "exit", "timed_out", "stdout", "stderr", "violations", "duration_s")} for x in r["results"]]}


def failure_evidence(replay):
    out = []
    for r in replay["results"]:
        if r["exit"] != 0:
            ref = excerpt_ref(replay, replay["label"])
            out.append({"label": "Observed failure", "kind": "log", "text": (ref or {}).get("text") or (r["stderr"] or r["stdout"])[-300:],
                        "ref": ref})
    return out


def build_finding(top, patched, before, after, fail, report, question, confirmed, model, tl):
    ch = top["change"]
    key = top["keys"][0] if top["keys"] else None
    needle = key
    ref_fail = excerpt_ref(fail, "after", needle)
    fail_line = ref_fail["text"] if ref_fail else "(no matching log line)"
    evid = [{"label": "Finding", "kind": "finding", "text": top["title"]}]
    if top["path"]:
        evid.append({"label": "Changed file", "kind": "source", "text": f"{top['path']} · line {top['line']}" if top["line"] else top["path"],
                     "ref": {"side": "after" if (ch.get("line_after") or ch["kind"] in ("modified", "added")) else "before", "path": top["path"], "line": top["line"]}})
    evid.append({"label": "Observed failure", "kind": "log", "text": fail_line, "ref": ref_fail})
    evid.append({"label": "Reproduction", "kind": "replay", "text": f"Undoing only this change makes every check pass (replay “undo {top['id']}”)."})
    patch = None
    if patched:
        chunks = [run_diff_patch(as_text(after[p]) if p in after else "", as_text(patched[p]) if p in patched else "", p)
                  for p in sorted(set(patched) | set(after)) if patched.get(p) != after.get(p) and p in patched and as_text(patched[p]) is not None]
        patch = "".join(chunks)
        if not patch and top["type"] == "file" and ch["kind"] == "added":
            patch = f"# Undo = delete {top['path']}\n"
    whole_file = top["type"] == "file"
    conf = "high" if top["score"] >= 5 and not whole_file else "medium"
    caveats = ["Diagnosis is an evidence-linked hypothesis. Review the patch before applying; Traceback never edits your project."]
    if whole_file:
        caveats.append("This fix restores an entire file, so it may be broader than the real defect; narrow it by hand.")
    alts = [{"id": c["id"], "title": c["title"], "score": c["score"]} for c, _ in confirmed[1:]]
    if alts:
        caveats.append("More than one change is individually sufficient; the one with the strongest textual link to the failure is shown first.")
    explanation = template_explanation(top, fail_line)
    source = "deterministic"
    if llm.enabled():
        res, err = llm.explain(question, {"cause": top["title"], "file": top["path"], "line": top["line"], "failure_line": fail_line,
                                          "replay_result": "undoing this change makes all checks pass", "confidence": conf})
        if res:
            explanation, source, model["used"] = res["explanation"], "model", True
            tl.add("model", "Model wrote the explanation from verified evidence", model_label())
        else:
            model["notes"].append("explain skipped: " + str(err))
    return {"title": top["title"], "confidence": conf, "explanation": explanation, "explanation_source": source,
            "evidence": evid, "patch": patch, "patch_applied": False, "alternatives": alts, "caveats": caveats}


def model_label():
    return f"{llm.model_name()} via Vultr Serverless Inference"


def template_explanation(top, fail_line):
    ch = top["change"]
    if top["type"] == "config" and ch["kind"] == "renamed":
        return (f"`{ch['key']}` was renamed to `{ch['new_key']}` in {top['path']}, but the startup check still reads `{ch['key']}`. "
                f"The failure output says: “{fail_line}”. Restoring the original key made every check pass in a fresh sandbox.")
    if top["type"] == "config":
        return (f"The setting `{top['keys'][0]}` was {ch['kind']} in {top['path']} and the checks fail afterwards ("
                f"“{fail_line}”). Undoing only that change made every check pass in a fresh sandbox.")
    if top["type"] == "dependency":
        return (f"The dependency `{top['keys'][0]}` changed ({ch['old'] or '—'} → {ch['new'] or '—'}) in {top['path']}. "
                f"Failure: “{fail_line}”. Reverting only that line made every check pass in a fresh sandbox.")
    return (f"{top['title']}. Failure: “{fail_line}”. Undoing only this change made every check pass in a fresh sandbox.")


# --- containment demo -----------------------------------------------------------------
def run_containment(sandbox=None):
    """Run a hostile fixture and prove: escape attempts blocked + logged, canary untouched and not leaked, workspace destroyed."""
    from .fixtures import containment_tree, CANARY_PATH
    sandbox = sandbox or Sandbox()
    tl = Timeline()
    os.makedirs(os.path.dirname(CANARY_PATH), exist_ok=True)
    token = "TB-CANARY-" + secrets.token_hex(8)
    with open(CANARY_PATH, "w") as f:
        f.write(token)
    h0 = _h(CANARY_PATH)
    tl.add("plan", "Control plane holds a canary secret outside the sandbox", CANARY_PATH)
    files = containment_tree()
    checks = [{"name": "sample script", "cmd": ["python", "sample.py"]}]
    tl.add("replay", "Running an untrusted sample script in a disposable sandbox", f"driver: {sandbox.driver}")
    r = sandbox.run(files, checks, "containment")
    res = r["results"][0]
    for v in res["violations"]:
        tl.add("blocked", f"BLOCKED · {v['event']}", str(v["target"]), {"kind": "violation"})
    leaked = token in (res["stdout"] + res["stderr"])
    after_h = _h(CANARY_PATH)
    tl.add("teardown", "Sandbox destroyed", f"workspace removed: {r['teardown']['workspace_removed']}")
    clean = sandbox.run({"hello.py": b"print('fresh sandbox ok')\n"}, [{"name": "reset check", "cmd": ["python", "hello.py"]}], "reset")
    tl.add("reset", "Fresh sandbox started — no state carried over", clean["results"][0]["stdout"].strip())
    checks_ok = {"escape_attempts_blocked": len(res["violations"]) >= 4, "canary_unchanged": h0 == after_h,
                 "canary_not_leaked": not leaked, "workspace_destroyed": r["teardown"]["workspace_removed"],
                 "reset_ok": clean["passed"]}
    verdict = "contained" if all(checks_ok.values()) else "NOT_CONTAINED"
    tl.add("verdict", f"Containment verdict: {verdict}", ", ".join(k for k, v in checks_ok.items() if not v) or "all checks passed")
    return {"verdict": verdict, "checks": checks_ok, "events": tl.events, "violations": res["violations"],
            "sandbox": {"driver": r["driver"], "limits": r["limits"], "teardown": r["teardown"]},
            "script_output": {"stdout": res["stdout"], "stderr": res["stderr"], "exit": res["exit"]}}


def _h(path):
    import hashlib
    try:
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        return None
