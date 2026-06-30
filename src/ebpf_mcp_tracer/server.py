"""
MCP server for LLM-driven bpftrace tracing.

Run this as the user/process that has permission to load BPF programs --
either root, or a python interpreter granted CAP_BPF + CAP_PERFMON via
setcap (see README). Talk to it over stdio from Claude Desktop or any
other MCP client; it is NOT meant to be exposed over a network port.
"""

import platform

from mcp.server.fastmcp import FastMCP

from . import engine, safety

mcp = FastMCP("ebpf-tracer")


@mcp.resource("ebpf://system/kernel-info")
def kernel_info() -> str:
    """Kernel version and bpftrace availability, so the LLM knows what it's working with."""
    available, detail = engine.is_bpftrace_available()
    return (
        f"kernel: {platform.release()}\n"
        f"bpftrace available: {available}\n"
        f"bpftrace info: {detail}"
    )


@mcp.tool()
def list_probes(pattern: str = "") -> dict:
    """
    List kernel probes available on this machine, optionally filtered by a
    glob pattern (e.g. 'tracepoint:syscalls:sys_enter_open*'). Read-only --
    use this before writing a script to confirm a probe actually exists on
    this kernel version rather than guessing.
    """
    return engine.list_probes(pattern)


@mcp.tool()
def validate_script(script: str) -> dict:
    """
    Checks a bpftrace script against this server's safety allowlist
    (probe types, blocked builtins) and then compiles it with `bpftrace -d`
    to catch syntax/type errors -- without attaching any probes or touching
    the running kernel. Always call this before run_trace.
    """
    violations = safety.validate_script(script)
    if violations:
        return {"ok": False, "stage": "safety", "violations": violations}

    compile_result = engine.dry_run(script)
    if not compile_result["ok"]:
        return {"ok": False, "stage": "compile", "error": compile_result["error"]}

    return {"ok": True, "message": "Passed safety checks and compiles cleanly."}


@mcp.tool()
def run_trace(script: str, duration_seconds: int = 10) -> dict:
    """
    Attaches the script's probes and collects events for up to
    duration_seconds (hard-capped at 60s server-side), then detaches.
    Re-runs the same safety checks as validate_script before doing anything
    -- this tool never trusts a prior validate_script call from the same
    conversation, since the script text could have changed.

    Returns events as a list of JSON objects (one per probe firing), plus
    any final map summaries bpftrace printed on exit.
    """
    violations = safety.validate_script(script)
    if violations:
        return {"ok": False, "stage": "safety", "violations": violations}

    return engine.run_trace(script, duration_seconds=duration_seconds)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
