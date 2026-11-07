"""Deterministic evidence extraction: config keys, dependencies, failure lines. No model involved."""
import difflib
import json
import os
import re

CONFIG_EXT = {".env", ".ini", ".cfg", ".conf", ".properties", ".yml", ".yaml", ".toml", ".json"}
NOT_CONFIG = {"package-lock.json", "package.json", "tsconfig.json", "traceback.json"}


def is_config(path):
    base = os.path.basename(path)
    if base in NOT_CONFIG or base.startswith("requirements"):
        return False
    return base.startswith(".env") or os.path.splitext(base)[1].lower() in CONFIG_EXT


def parse_config(path, text):
    """-> {key: {"value", "line", "raw"}}. Flat/dotted keys; line numbers are 1-based."""
    out = {}
    lines = text.splitlines()
    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        try:
            data = json.loads(text)
        except ValueError:
            return out

        def walk(node, prefix):
            if isinstance(node, dict):
                for k, v in node.items():
                    walk(v, f"{prefix}.{k}" if prefix else k)
            else:
                last = prefix.split(".")[-1]
                ln = next((i + 1 for i, l in enumerate(lines) if f'"{last}"' in l), 0)
                out[prefix] = {"value": str(node), "line": ln, "raw": lines[ln - 1] if ln else ""}
        walk(data, "")
        return out
    section, stack = "", []
    for i, raw in enumerate(lines, 1):
        s = raw.strip()
        if not s or s.startswith(("#", ";", "//")):
            continue
        if ext == ".toml" or ext in (".ini", ".cfg", ".conf"):
            m = re.match(r"^\[(.+)\]$", s)
            if m:
                section = m.group(1)
                continue
        if ext in (".yml", ".yaml"):
            indent = len(raw) - len(raw.lstrip())
            while stack and stack[-1][0] >= indent:
                stack.pop()
            m = re.match(r"^([\w.\-]+)\s*:\s*(.*)$", s)
            if not m:
                continue
            key = ".".join([k for _, k in stack] + [m.group(1)])
            if m.group(2) == "":
                stack.append((indent, m.group(1)))
            else:
                out[key] = {"value": m.group(2).strip("'\""), "line": i, "raw": raw}
            continue
        m = re.match(r"^(?:export\s+)?([A-Za-z_][\w.\-]*)\s*[=:]\s*(.*)$", s)
        if m:
            key = f"{section}.{m.group(1)}" if section else m.group(1)
            out[key] = {"value": m.group(2).strip().strip("'\""), "line": i, "raw": raw}
    return out


def config_changes(before, after, text):
    """before/after: {path: bytes}; text: bytes->str|None."""
    changes = []
    for path in sorted(set(before) | set(after)):
        if not is_config(path):
            continue
        bt = text(before[path]) if path in before else ""
        at = text(after[path]) if path in after else ""
        if bt is None or at is None or bt == at:
            continue
        b, a = parse_config(path, bt), parse_config(path, at)
        removed = {k: v for k, v in b.items() if k not in a}
        added = {k: v for k, v in a.items() if k not in b}
        for k in sorted(set(b) & set(a)):
            if b[k]["value"] != a[k]["value"]:
                changes.append({"kind": "changed", "path": path, "key": k, "old": b[k]["value"], "new": a[k]["value"],
                                "line_before": b[k]["line"], "line_after": a[k]["line"],
                                "before_line_text": b[k]["raw"], "after_line_text": a[k]["raw"]})
        paired = set()
        for rk, rv in removed.items():  # rename = removed key + added key with same value or similar name
            best = None
            for ak, av in added.items():
                if ak in paired:
                    continue
                score = difflib.SequenceMatcher(None, rk.lower(), ak.lower()).ratio() + (0.5 if rv["value"] and rv["value"] == av["value"] else 0)
                if score >= 0.9 and (best is None or score > best[0]):
                    best = (score, ak)
            if best:
                av = added[best[1]]
                paired.add(best[1])
                changes.append({"kind": "renamed", "path": path, "key": rk, "new_key": best[1], "old": rv["value"], "new": av["value"],
                                "line_before": rv["line"], "line_after": av["line"],
                                "before_line_text": rv["raw"], "after_line_text": av["raw"]})
            else:
                changes.append({"kind": "removed", "path": path, "key": rk, "old": rv["value"], "new": None,
                                "line_before": rv["line"], "line_after": None, "before_line_text": rv["raw"], "after_line_text": None})
        for ak, av in added.items():
            if ak not in paired:
                changes.append({"kind": "added", "path": path, "key": ak, "old": None, "new": av["value"],
                                "line_before": None, "line_after": av["line"], "before_line_text": None, "after_line_text": av["raw"]})
    return changes


def parse_requirements(text):
    out = {}
    for i, raw in enumerate(text.splitlines(), 1):
        s = raw.split("#")[0].strip()
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(.*)$", s)
        if m and not s.startswith("-"):
            out[m.group(1).lower()] = {"spec": m.group(2) or "*", "line": i, "raw": raw}
    return out


def parse_package_json(text):
    out = {}
    try:
        data = json.loads(text)
    except ValueError:
        return out
    lines = text.splitlines()
    for sect in ("dependencies", "devDependencies"):
        for k, v in (data.get(sect) or {}).items():
            ln = next((i + 1 for i, l in enumerate(lines) if f'"{k}"' in l), 0)
            out[k.lower()] = {"spec": str(v), "line": ln, "raw": lines[ln - 1] if ln else ""}
    return out


def dependency_changes(before, after, text):
    changes = []
    for path in sorted(set(before) | set(after)):
        base = os.path.basename(path)
        if base.startswith("requirements") and base.endswith(".txt"):
            parse = parse_requirements
        elif base == "package.json":
            parse = parse_package_json
        else:
            continue
        bt = text(before[path]) if path in before else ""
        at = text(after[path]) if path in after else ""
        if bt is None or at is None or bt == at:
            continue
        b, a = parse(bt), parse(at)
        for name in sorted(set(b) | set(a)):
            bs, as_ = b.get(name), a.get(name)
            if bs and as_ and bs["spec"] == as_["spec"]:
                continue
            kind = "changed" if bs and as_ else ("removed" if bs else "added")
            changes.append({"kind": kind, "path": path, "package": name,
                            "old": bs and bs["spec"], "new": as_ and as_["spec"],
                            "line_before": bs and bs["line"], "line_after": as_ and as_["line"],
                            "before_line_text": bs and bs["raw"], "after_line_text": as_ and as_["raw"]})
    return changes


ERR_RE = re.compile(r"(error|exception|traceback|fail|missing|not found|no module|cannot|denied|refused|invalid)", re.I)


def error_lines(output, limit=8):
    """[(line_no_1based, text)] of the lines most likely to describe the failure."""
    hits = [(i + 1, l.strip()) for i, l in enumerate(output.splitlines()) if ERR_RE.search(l)]
    return hits[-limit:]


def traceback_frames(output):
    return [(m.group(1), int(m.group(2))) for m in re.finditer(r'File "([^"]+)", line (\d+)', output)]
