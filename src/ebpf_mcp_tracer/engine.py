"""
Wraps the bpftrace binary as a subprocess. Two operations:

  dry_run()  -- compiles the script without attaching any probes, so syntax
                and type errors surface immediately (this is the closest
                analogue to the eBPF verifier feedback loop -- bpftrace's
                own compiler catches most of what the kernel verifier would
                reject, before we even ask for root-level attachment).

  run_trace() -- actually attaches and streams events for a bounded duration,
                 then detaches cleanly.

Neither function ever passes --unsafe. That flag is what would unlock
system(), unsafe map ops, and a few other things -- it's the single most
important line NOT to add to this file.
"""

import json
import os
import shutil
import signal
import subprocess
import tempfile

BPFTRACE_BIN = shutil.which("bpftrace") or "bpftrace"

MAX_TRACE_SECONDS = 60       # hard ceiling regardless of what's requested
MAX_EVENTS = 500              # truncate rather than flood the LLM's context
MAX_STDERR_CHARS = 4000


def is_bpftrace_available() -> tuple[bool, str]:
    if shutil.which("bpftrace") is None:
        return False, "bpftrace is not on PATH. Install it (e.g. 'apt install bpftrace') and ensure it's runnable."
    try:
        proc = subprocess.run([BPFTRACE_BIN, "--version"], capture_output=True, text=True, timeout=5)
        return True, proc.stdout.strip() or proc.stderr.strip()
    except Exception as exc:  # noqa: BLE001 - surface whatever went wrong to the caller
        return False, f"bpftrace found but failed to run: {exc}"


def list_probes(pattern: str = "") -> dict:
    """
    Lists kernel probes matching a glob pattern via `bpftrace -l`, e.g.
    pattern='tracepoint:syscalls:sys_enter_open*'. This is read-only and
    doesn't attach anything -- listing isn't gated by the safety allowlist,
    only attaching/running is.
    """
    cmd = [BPFTRACE_BIN, "-l"]
    if pattern:
        cmd.append(pattern)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "bpftrace -l timed out"}
    except FileNotFoundError:
        return {"ok": False, "error": "bpftrace binary not found"}

    probes = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    return {
        "ok": proc.returncode == 0,
        "probes": probes[:300],
        "truncated": len(probes) > 300,
        "stderr": proc.stderr.strip()[:MAX_STDERR_CHARS] if proc.returncode != 0 else "",
    }


def dry_run(script: str, timeout: int = 5) -> dict:
    """Compile-only check: `bpftrace -d` dumps IR and exits without attaching."""
    fd, path = tempfile.mkstemp(suffix=".bt")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(script)
        try:
            proc = subprocess.run(
                [BPFTRACE_BIN, "-d", path],
                capture_output=True, text=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": "Compile check timed out after 5s."}

        if proc.returncode == 0:
            return {"ok": True, "message": "Compiles cleanly. No probes attached yet."}
        return {
            "ok": False,
            "error": proc.stderr.strip()[-MAX_STDERR_CHARS:] or "Unknown compile error (no stderr captured).",
        }
    finally:
        os.unlink(path)


def run_trace(script: str, duration_seconds: int = 10) -> dict:
    """
    Attaches the script's probes and collects events for duration_seconds,
    then sends SIGINT (which bpftrace treats as "stop and print any final
    map summaries") rather than killing it outright, so map-aggregated
    scripts (e.g. @[comm] = count();) still report their results.
    """
    duration_seconds = max(1, min(duration_seconds, MAX_TRACE_SECONDS))

    fd, path = tempfile.mkstemp(suffix=".bt")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(script)

        proc = subprocess.Popen(
            [BPFTRACE_BIN, "-f", "json", path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,  # so we can signal the whole process group
        )

        try:
            stdout, stderr = proc.communicate(timeout=duration_seconds)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGINT)
                stdout, stderr = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                stdout, stderr = proc.communicate()

        if proc.returncode not in (0, None) and proc.returncode != -signal.SIGINT and not stdout:
            return {
                "ok": False,
                "error": stderr.strip()[-MAX_STDERR_CHARS:] or f"bpftrace exited with code {proc.returncode}",
            }

        events = []
        parse_errors = 0
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                parse_errors += 1

        truncated = len(events) > MAX_EVENTS
        return {
            "ok": True,
            "events": events[:MAX_EVENTS],
            "event_count": len(events),
            "truncated": truncated,
            "unparsed_lines": parse_errors,
            "stderr": stderr.strip()[-MAX_STDERR_CHARS:] if stderr.strip() else "",
        }
    finally:
        os.unlink(path)
