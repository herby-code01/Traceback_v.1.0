"""Safe snapshot loading and deterministic diffing."""
import difflib
import hashlib
import os
import zipfile

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".mypy_cache", ".pytest_cache", "__MACOSX"}
MAX_FILES, MAX_TOTAL, MAX_FILE = 2000, 50 * 1024 * 1024, 5 * 1024 * 1024


class SnapshotError(Exception):
    pass


def load_zip(path):
    """Return {relpath: bytes}. Never touches disk (no zip-slip possible); rejects abusive archives."""
    try:
        z = zipfile.ZipFile(path)
    except zipfile.BadZipFile as e:
        raise SnapshotError("not a valid ZIP file") from e
    with z:
        infos = [i for i in z.infolist() if not i.is_dir()]
        if len(infos) > MAX_FILES:
            raise SnapshotError(f"too many files (>{MAX_FILES})")
        if sum(i.file_size for i in infos) > MAX_TOTAL:
            raise SnapshotError("snapshot too large when extracted")
        keep = []
        for i in infos:
            name = i.filename.replace("\\", "/")
            parts = name.split("/")
            if name.startswith("/") or ".." in parts:
                raise SnapshotError(f"unsafe path in ZIP: {name}")
            if (i.external_attr >> 16) & 0o170000 == 0o120000:
                continue  # symlink: ignore
            if any(p in SKIP_DIRS for p in parts):
                continue
            if i.file_size > MAX_FILE:
                continue
            keep.append((name, i))
        if keep and all("/" in n for n, _ in keep) and len({n.split("/")[0] for n, _ in keep}) == 1:
            keep = [(n.split("/", 1)[1], i) for n, i in keep]
        return {n: z.read(i) for n, i in keep}


def as_text(data):
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def sha(data):
    return hashlib.sha256(data).hexdigest()[:12]


def diff_trees(before, after):
    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    modified, unchanged = [], 0
    for p in sorted(set(before) & set(after)):
        if before[p] == after[p]:
            unchanged += 1
            continue
        bt, at = as_text(before[p]), as_text(after[p])
        entry = {"path": p, "before_hash": sha(before[p]), "after_hash": sha(after[p]), "text": bt is not None and at is not None}
        if entry["text"]:
            bl, al = bt.splitlines(), at.splitlines()
            entry["unified"] = "".join(l if l.endswith("\n") else l + "\n" for l in difflib.unified_diff(
                bl, al, f"before/{p}", f"after/{p}", lineterm="", n=2))[:20000]
            sm = difflib.SequenceMatcher(None, bl, al, autojunk=False)
            entry["changed_after_lines"] = [(j1 + 1, j2) for tag, i1, i2, j1, j2 in sm.get_opcodes() if tag != "equal" and j2 > j1]
        modified.append(entry)
    return {"added": added, "removed": removed, "modified": modified, "unchanged": unchanged}
