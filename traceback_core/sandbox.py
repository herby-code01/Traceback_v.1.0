"""Disposable sandbox: one fresh workspace per run, destroyed in `finally`.

Drivers
  docker : production on the Vultr VM. --network none, read-only rootfs, all caps dropped,
           uid 1000, pids/mem/cpu limits, tmpfs /tmp, workspace is the only writable mount.
  ns     : local/dev fallback. `unshare -Urn` (user + network namespace => no network),
           rlimits, scrubbed env, plus the audit-hook guard. Weaker than docker; the report
           always says which driver produced the evidence.
The control plane never puts its own secrets in the worker environment.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, asdict

GUARD = os.path.join(os.path.dirname(os.path.abspath(__file__)), "guard.py")
MARK = "@@TB@@"


@dataclass
class Limits:
    timeout_s: int = 10
    mem_mb: int = 512
    cpu_s: int = 10
    fsize_mb: int = 8
    out_bytes: int = 64 * 1024
    network: str = "off"


def docker_available():
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=8).returncode == 0
    except Exception:
        return False


def pick_driver():
    want = os.environ.get("SANDBOX_DRIVER", "auto")
    if want in ("docker", "ns"):
        return want
    return "docker" if docker_available() else "ns"


class Sandbox:
    def __init__(self, limits=None, driver=None, root=None):
        self.limits = limits or Limits()
        self.driver = driver or pick_driver()
        self.root = root or os.environ.get("SANDBOX_ROOT") or os.path.join(tempfile.gettempdir(), "traceback-sandboxes")
        os.makedirs(self.root, exist_ok=True)
        self.image = os.environ.get("SANDBOX_IMAGE", "python:3.12-slim")

    # -- public --------------------------------------------------------------
    def run(self, files, checks, label=""):
        """files: {relpath: bytes}. checks: [{name, cmd:[python, script, ...]}]."""
        run_id = uuid.uuid4().hex[:10]
        ws = os.path.join(self.root, "ws-" + run_id)
        started = time.time()
        results = []
        try:
            os.makedirs(ws)
            for rel, data in files.items():
                dest = os.path.join(ws, rel)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with open(dest, "wb") as f:
                    f.write(data)
            if self.driver == "docker":
                for dp, dn, fn in os.walk(ws):  # uid 1000 in the container must be able to write
                    os.chmod(dp, 0o777)
                    for n in fn:
                        os.chmod(os.path.join(dp, n), 0o666)
            for chk in checks:
                results.append(self._run_one(ws, chk, run_id))
        finally:
            shutil.rmtree(ws, ignore_errors=True)
        teardown = {"workspace_removed": not os.path.exists(ws), "workspace": os.path.basename(ws)}
        if self.driver == "docker":
            left = subprocess.run(["docker", "ps", "-aq", "--filter", f"name=tb-{run_id}"],
                                  capture_output=True, text=True).stdout.strip()
            teardown["container_removed"] = left == ""
        return {"label": label, "run_id": run_id, "driver": self.driver, "limits": asdict(self.limits),
                "started": started, "duration_s": round(time.time() - started, 3),
                "results": results, "teardown": teardown,
                "passed": bool(results) and all(r["exit"] == 0 and not r["timed_out"] for r in results)}

    # -- internals -----------------------------------------------------------
    def _target(self, chk):
        cmd = chk["cmd"]
        if not cmd or cmd[0] not in ("python", "python3"):
            raise ValueError("checks must be `python <script> [args]` in this version")
        return cmd[1:]

    def _run_one(self, ws, chk, run_id):
        lim = self.limits
        target = self._target(chk)
        guard_args = [str(lim.mem_mb), str(lim.cpu_s), str(lim.fsize_mb), "--"] + target
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": ws, "LANG": "C.UTF-8"}
        if self.driver == "docker":
            name = f"tb-{run_id}"
            cmd = ["docker", "run", "--rm", "--name", name, "--network", "none", "--read-only",
                   "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "64",
                   "--memory", f"{lim.mem_mb + 128}m", "--memory-swap", f"{lim.mem_mb + 128}m",
                   "--cpus", "0.5", "--user", "1000:1000", "--tmpfs", "/tmp:rw,noexec,size=16m",
                   "-v", f"{ws}:/work:rw", "-v", f"{GUARD}:/guard/guard.py:ro", "-w", "/work",
                   "-e", "HOME=/work", "-e", "LANG=C.UTF-8", self.image,
                   "python", "-I", "/guard/guard.py", "/work"] + guard_args
            run_env = None
        else:
            cmd = ["unshare", "-Urn", "--", sys.executable, "-I", GUARD, ws] + guard_args
            run_env = env
        t0 = time.time()
        timed_out = False
        try:
            p = subprocess.Popen(cmd, cwd=ws if self.driver == "ns" else None, env=run_env,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            try:
                out, err = p.communicate(timeout=lim.timeout_s)
            except subprocess.TimeoutExpired:
                timed_out = True
                if self.driver == "docker":
                    subprocess.run(["docker", "kill", f"tb-{run_id}"], capture_output=True)
                try:
                    os.killpg(p.pid, 9)
                except ProcessLookupError:
                    pass
                out, err = p.communicate()
            code = p.returncode
        except FileNotFoundError as e:
            out, err, code = b"", f"sandbox driver unavailable: {e}".encode(), 127
        violations, clean_err = [], []
        for line in err.decode("utf-8", "replace").splitlines():
            if line.startswith(MARK):
                try:
                    violations.append(json.loads(line[len(MARK):]))
                except ValueError:
                    pass
            else:
                clean_err.append(line)
        cap = lim.out_bytes
        stdout = out[:cap].decode("utf-8", "replace")
        stderr = "\n".join(clean_err)[:cap]
        return {"name": chk["name"], "cmd": chk["cmd"], "exit": code if not timed_out else 124,
                "timed_out": timed_out, "stdout": stdout, "stderr": stderr,
                "violations": violations, "duration_s": round(time.time() - t0, 3)}
