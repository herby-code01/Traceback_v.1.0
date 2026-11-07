"""In-sandbox guard. Runs INSIDE the isolated worker (never imported by the control plane).

usage: guard.py <workspace> <mem_mb> <cpu_s> <fsize_mb> -- <script.py> [args...]

Layer 2 of containment (layer 1 is the OS: network namespace / docker --network none).
It sets resource limits, then installs a Python audit hook that blocks and LOGS any
file access outside the workspace, any network call, any subprocess and ctypes use.
Violations are emitted as `@@TB@@{json}` lines on stderr *before* the error is raised,
so a script that catches the exception still leaves a record.

Honest limit: an audit hook is not a security boundary by itself (native code can
bypass it). That is why the OS-level layer is mandatory and this one is for evidence.
"""
import json
import os
import resource
import runpy
import sys
import traceback

MARK = "@@TB@@"


def main():
    argv = sys.argv[1:]
    sep = argv.index("--")
    ws = os.path.realpath(argv[0])
    mem_mb, cpu_s, fsize_mb = int(argv[1]), int(argv[2]), int(argv[3])
    target = argv[sep + 1:]

    resource.setrlimit(resource.RLIMIT_CPU, (cpu_s, cpu_s))
    resource.setrlimit(resource.RLIMIT_AS, (mem_mb << 20, mem_mb << 20))
    resource.setrlimit(resource.RLIMIT_FSIZE, (fsize_mb << 20, fsize_mb << 20))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    os.chdir(ws)
    sys.dont_write_bytecode = True

    read_roots = {ws, "/dev/null", "/dev/urandom", "/dev/zero", "/proc/self",
                  os.path.realpath(sys.prefix), os.path.realpath(sys.base_prefix),
                  os.path.realpath(sys.exec_prefix), "/usr/lib", "/lib", "/usr/local/lib"}
    for p in sys.path:
        if p and os.path.isdir(p) or p.endswith(".zip"):
            rp = os.path.realpath(p)
            if rp != "/":
                read_roots.add(rp)

    def within(path, roots):
        rp = os.path.realpath(path)
        return any(rp == r or rp.startswith(r.rstrip("/") + "/") for r in roots)

    def block(event, target_desc):
        sys.stderr.flush()
        os.write(2, (MARK + json.dumps({"event": event, "target": str(target_desc)}) + "\n").encode())
        raise PermissionError(f"Blocked by Traceback sandbox: {event} {target_desc}")

    def as_path(x):
        if isinstance(x, bytes):
            return os.fsdecode(x)
        if isinstance(x, (str, os.PathLike)):
            return os.fspath(x)
        return None  # file descriptor or None

    WRITE = {"os.remove", "os.rmdir", "os.mkdir", "os.chmod", "os.chown", "os.truncate",
             "os.rename", "os.link", "os.symlink", "shutil.rmtree", "shutil.copyfile",
             "shutil.copytree", "shutil.move", "os.utime", "os.mkfifo", "os.mknod"}
    LIST = {"os.listdir", "os.scandir", "glob.glob"}
    NET = {"socket.connect", "socket.bind", "socket.sendto", "socket.sendmsg",
           "socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr",
           "socket.gethostbyname_ex"}
    EXEC = {"subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn",
            "os.fork", "os.forkpty"}

    def hook(event, args):
        if event == "open":
            p = as_path(args[0])
            if p is None:
                return
            mode, flags = args[1], args[2] if len(args) > 2 else 0
            writing = (isinstance(mode, str) and any(c in mode for c in "wax+")) or \
                      (isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC))
            if writing:
                if not within(p, {ws}):
                    block("file.write_outside_workspace", p)
            elif not within(p, read_roots):
                block("file.read_outside_workspace", p)
        elif event in WRITE:
            for a in args[:2]:
                p = as_path(a)
                if p is not None and not within(p, {ws}):
                    block("file.write_outside_workspace", p)
        elif event in LIST:
            p = as_path(args[0]) if args else None
            if p is not None and not within(p, read_roots):
                block("file.list_outside_workspace", p)
        elif event in NET:
            name = event.split(".", 1)[1]
            tgt = args[0] if name.startswith("gethostby") or name == "getaddrinfo" else (args[1] if len(args) > 1 else "")
            block("network." + name, tgt)
        elif event in EXEC:
            block("process." + event, args[0] if args else "")
        elif event.startswith("ctypes."):
            block("native." + event, "")

    sys.addaudithook(hook)
    sys.argv = target
    sys.path.insert(0, ws)
    try:
        runpy.run_path(target[0], run_name="__main__")
    except SystemExit:
        raise
    except BaseException as e:  # print a traceback that starts at project code
        tb = e.__traceback__
        while tb and not os.path.realpath(tb.tb_frame.f_code.co_filename).startswith(ws):
            tb = tb.tb_next
        traceback.print_exception(type(e), e, tb or e.__traceback__)
        sys.exit(1)


if __name__ == "__main__":
    main()
