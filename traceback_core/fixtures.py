"""Bundled demo fixtures (also exported as ZIPs by `python -m traceback_core.fixtures`)."""
import io
import json
import os
import sys
import zipfile

CANARY_PATH = os.path.join(os.environ.get("TMPDIR", "/tmp"), "traceback-canary", "secret.txt")

STARTUP_CHECK = '''"""Startup check: verifies required settings exist before the app boots."""
from pathlib import Path

REQUIRED = ["SECRET_KEY", "DATABASE_URL"]


def load(path):
    cfg = {}
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            cfg[key.strip()] = value.strip()
    return cfg


def main():
    cfg = load(".env.example")
    for key in REQUIRED:
        if key not in cfg:
            raise RuntimeError(f"Startup check failed: missing required setting {key}")
    print("Startup check passed: all required settings present")


if __name__ == "__main__":
    main()
'''

MANIFEST = json.dumps({"checks": [{"name": "startup check", "cmd": ["python", "startup_check.py"]}]}, indent=2) + "\n"


def known_bug():
    before = {
        "traceback.json": MANIFEST,
        ".env.example": "# Example environment for the Orbit API\nAPP_ENV=production\nSECRET_KEY=change-me\nDATABASE_URL=sqlite:///orbit.db\nLOG_LEVEL=info\n",
        "startup_check.py": STARTUP_CHECK,
        "app.py": 'def health():\n    """Liveness probe."""\n    return {"status": "ok"}\n',
        "requirements.txt": "flask==3.0.0\nrequests==2.31.0\n",
        "README.md": "# Orbit API\nSmall demo service.\n",
    }
    after = dict(before)
    after[".env.example"] = "# Example environment for the Orbit API\nAPP_ENV=production\nSECRET_KEY=change-me\nDB_URL=sqlite:///orbit.db\nLOG_LEVEL=info\n"
    after["app.py"] = 'def health():\n    """Liveness probe (v2)."""\n    return {"status": "ok", "version": 2}\n'  # unrelated noise
    after["requirements.txt"] = "flask==3.0.2\nrequests==2.31.0\n"  # unrelated noise
    after["README.md"] = "# Orbit API\nSmall demo service. Now with v2.\n"
    return _b(before), _b(after)


def inconclusive():
    check = ('from pathlib import Path\n\nif not Path("data/seed.db").exists():\n'
             '    raise SystemExit("seed database not found: data/seed.db (provisioned outside the repo)")\nprint("ok")\n')
    before = {"traceback.json": MANIFEST.replace("startup_check.py", "check.py"), "check.py": check, "app.py": "VERSION = 1\n"}
    after = dict(before)
    after["app.py"] = "VERSION = 2\n"
    return _b(before), _b(after)


SAMPLE = '''"""An 'untrusted' project script that behaves badly. Every attempt must be blocked and logged."""
import os, socket, subprocess

def attempt(name, fn):
    try:
        fn()
        print(f"ESCAPED  {name}")
    except Exception as e:
        print(f"blocked  {name}: {type(e).__name__}")

attempt("read /etc/passwd", lambda: open("/etc/passwd").read())
attempt("read control-plane canary", lambda: open(%r).read())
attempt("write outside workspace", lambda: open("/tmp/traceback-pwned", "w").write("x"))
attempt("list /", lambda: os.listdir("/"))
attempt("call home over network", lambda: socket.create_connection(("1.1.1.1", 80), timeout=2))
attempt("spawn a shell", lambda: subprocess.run(["sh", "-c", "id"]))
open("notes.txt", "w").write("inside the workspace is fine\\n")
print("script finished")
''' % CANARY_PATH


def containment_tree():
    return {"sample.py": SAMPLE.encode()}


def _b(tree):
    return {k: v.encode() if isinstance(v, str) else v for k, v in tree.items()}


FIXTURES = {"known-bug": known_bug, "inconclusive": inconclusive}


def write_zips(outdir):
    os.makedirs(outdir, exist_ok=True)
    for name, fn in FIXTURES.items():
        for side, tree in zip(("before", "after"), fn()):
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
                for p, data in tree.items():
                    z.writestr(f"orbit/{p}", data)
            with open(os.path.join(outdir, f"{name}-{side}.zip"), "wb") as f:
                f.write(buf.getvalue())


if __name__ == "__main__":
    write_zips(sys.argv[1] if len(sys.argv) > 1 else "fixtures")
    print("wrote fixtures")
