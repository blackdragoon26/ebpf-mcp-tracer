"""
Safety guardrails for LLM-generated bpftrace scripts.

This is the gate between an LLM and root-level kernel tracing. Nothing in
engine.py should run a script that hasn't passed through validate_script()
first. Keep this file boring and explicit -- it is the part of the project
that actually matters.
"""

import re

# Probe specifiers we allow. Each is a regex matched against the probe
# header (the part before the opening brace), e.g. "kprobe:vfs_open".
# Wildcards like "kprobe:*" or "kprobe:do_*" are deliberately NOT allowed --
# every hookable function must be named explicitly in this list, or you
# extend the list yourself after reviewing what that function does.
ALLOWED_PROBE_PATTERNS = [
    r"^BEGIN$",
    r"^END$",
    r"^interval:s:\d+$",
    r"^interval:ms:\d+$",
    r"^profile:hz:\d+$",
    r"^tracepoint:syscalls:sys_(enter|exit)_\w+$",
    r"^tracepoint:sched:sched_\w+$",
    r"^tracepoint:net:\w+$",
    r"^tracepoint:block:\w+$",
    r"^tracepoint:tcp:\w+$",
    r"^kprobe:vfs_(open|read|write|unlink|mkdir|rmdir)$",
    r"^kretprobe:vfs_(open|read|write|unlink|mkdir|rmdir)$",
    r"^kprobe:tcp_(connect|sendmsg|recvmsg|close)$",
    r"^kretprobe:tcp_(connect|sendmsg|recvmsg|close)$",
    r"^kprobe:(do_sys_open|do_unlinkat)$",
    r"^kretprobe:(do_sys_open|do_unlinkat)$",
]

# Builtins that can affect the system rather than just observe it, or that
# can be used to defeat the probe whitelist above (e.g. override() changes
# a traced function's return value -- that's an action, not a trace).
# bpftrace already requires --unsafe for some of these; we never pass
# --unsafe, but we still block them at the script level so the error is
# clear instead of a silent compile failure.
DANGEROUS_BUILTINS = [
    "system(",
    "override(",
    "signal(",
    "skboutput(",
]

# A probe line looks like one of:
#   kprobe:vfs_open
#   tracepoint:syscalls:sys_enter_openat,
#   BEGIN {
# This pulls out everything before the first "{" or "," on each
# non-blank, non-comment line that isn't inside a block body.
_PROBE_HEADER_RE = re.compile(r"^\s*([A-Za-z][\w:\.\*]*(?:\s*,\s*[A-Za-z][\w:\.\*]*)*)\s*\{")


def extract_probe_headers(script: str) -> list[str]:
    """Pull probe specifiers (e.g. 'kprobe:vfs_open') out of a bpftrace script."""
    # bpftrace allows a multi-probe header to span several lines as long as
    # each line but the last ends with a trailing comma. Collapse those
    # before scanning so extraction doesn't depend on formatting.
    joined = re.sub(r",\s*\n\s*", ", ", script)

    headers = []
    for line in joined.splitlines():
        match = _PROBE_HEADER_RE.match(line)
        if not match:
            continue
        for probe in match.group(1).split(","):
            headers.append(probe.strip())
    return headers


def validate_script(script: str) -> list[str]:
    """
    Returns a list of violation strings. Empty list means the script is safe
    to compile/run. Never returns partial trust -- either zero violations
    (proceed) or a non-empty list (refuse and surface it to the LLM).
    """
    violations: list[str] = []

    if not script.strip():
        violations.append("Script is empty.")
        return violations

    for builtin in DANGEROUS_BUILTINS:
        if builtin in script:
            violations.append(
                f"Use of '{builtin.rstrip('(')}' is blocked. This builtin can "
                f"modify system state or program behavior rather than just "
                f"observing it, and is outside what this server permits."
            )

    headers = extract_probe_headers(script)
    if not headers:
        violations.append(
            "Could not find any probe headers (e.g. 'kprobe:vfs_open { ... }'). "
            "Every bpftrace script needs at least one probe."
        )

    for probe in headers:
        if not any(re.match(pattern, probe) for pattern in ALLOWED_PROBE_PATTERNS):
            violations.append(
                f"Probe '{probe}' is not on the allowlist. If this is a function "
                f"you genuinely need to trace, add an explicit pattern for it to "
                f"ALLOWED_PROBE_PATTERNS in safety.py after checking what it does -- "
                f"do not widen this to a wildcard."
            )

    return violations
