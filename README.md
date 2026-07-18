# ebpf-mcp-tracer

An MCP server that lets an LLM write and run bpftrace scripts against your
kernel, gated by an explicit probe allowlist and a hard execution timeout.

It does **not** compile raw eBPF C. bpftrace is the engine -- it already
handles BTF/CO-RE portability, hook attachment, and ring-buffer-to-text
formatting, so this project is the orchestration and safety layer on top
of it rather than a from-scratch eBPF compiler.

The `ebpf-mcp-tracer` is a secure MCP server that bridges LLMs and the Linux kernel by orchestrating `bpftrace` for natural-language, kernel-level observability. Instead of compiling raw eBPF C, it leverages `bpftrace`'s built-in safety and portability while enforcing strict guardrails through explicit probe allowlists, blocked dangerous builtins, and hard execution timeouts. By exposing simple tools for probe discovery, dry-run validation, and timed trace execution over local stdio, it empowers AI agents to safely debug complex system bottlenecks and analyze process behavior without requiring deep eBPF expertise or risking host stability.

## What it exposes

Three tools, callable by any MCP client (Claude Desktop, etc.):

- `list_probes(pattern)` -- read-only listing of kernel probes (`bpftrace -l`)
- `validate_script(script)` -- safety allowlist check + compile-only dry run
  (`bpftrace -d`, no attachment)
- `run_trace(script, duration_seconds)` -- attaches and streams events for up
  to 60s, then detaches and returns parsed JSON events

And one resource: `ebpf://system/kernel-info` (kernel version, bpftrace
availability).

## System Architecture
<img width="932" height="1342" alt="image" src="https://github.com/user-attachments/assets/e9ccfb55-7d90-4b47-882c-b4b1147f38bf" />


## Setup on your machine

1. Install bpftrace:
   ```
   sudo apt update && sudo apt install -y bpftrace
   ```
   Confirm it works standalone first:
   ```
   sudo bpftrace -e 'BEGIN { printf("it works\n"); exit(); }'
   ```

2. Install the Python deps:
   ```
   cd ebpf-mcp-tracer
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Permissions.** bpftrace needs to load BPF programs into the kernel,
   which normally requires root. You have two options:

   - **Simplest:** run the MCP server process itself as root. Fine for a
     personal box, not something to do on a shared machine.

   - **Better, if your kernel is 5.8+:** grant the venv's python binary the
     specific capabilities bpftrace needs instead of full root:
     ```
     sudo setcap cap_bpf,cap_perfmon,cap_sys_resource+ep $(readlink -f venv/bin/python3)
     ```
     Note this grants those capabilities to *any* script run by that exact
     python binary -- keep the venv dedicated to this project.

4. Test the server directly before wiring it into a client:
   ```
   python3 -m mcp dev src/ebpf_mcp_tracer/server.py
   ```
   or run it raw and talk to it over stdio:
   ```
   python3 src/ebpf_mcp_tracer/server.py
   ```

5. Point your MCP client at it. Example Claude Desktop config entry:
   ```json
   {
     "mcpServers": {
       "ebpf-tracer": {
         "command": "/absolute/path/to/ebpf-mcp-tracer/venv/bin/python3",
         "args": ["/absolute/path/to/ebpf-mcp-tracer/src/ebpf_mcp_tracer/server.py"]
       }
     }
   }
   ```
   (Verify the exact config file location and key names against current
   Claude Desktop docs -- this has changed before.)

## Running the tests

The safety-allowlist tests need no privileges and no bpftrace install:
```
pip install pytest
python3 -m pytest tests/test_safety.py -v
```

There's also a fake bpftrace shim at `tests/fakebin/bpftrace` used during
development to exercise the subprocess/timeout/JSON-parsing logic in
`engine.py` without needing a real kernel. You shouldn't need it once you
have the real binary installed, but it's there if you want to test changes
to `engine.py` without root.

## Extending the probe allowlist

`src/ebpf_mcp_tracer/safety.py` has `ALLOWED_PROBE_PATTERNS`. Every probe
the LLM can attach to must match one of these regexes -- there are no
wildcards on purpose. To add a new function:

1. Look up what it does and confirm it's safe to hook (read-only tracing,
   not something that can be abused to leak secrets across processes or
   degrade performance under load).
2. Add an explicit pattern, e.g. `r"^kprobe:tcp_v4_connect$"`.
3. Re-run the safety tests.

Don't add `kprobe:*` or `kprobe:do_*`-style wildcards -- that defeats the
point of the allowlist.


## For furthur documentation
Look into https://github.com/blackdragoon26/ebpf-mcp-tracer/blob/main/INSTALL.md

## What's deliberately NOT here yet

- No `--unsafe` flag anywhere, which means `system()`, `override()`, and a
  few other dangerous bpftrace builtins are unreachable even if the
  allowlist regex check somehow had a hole. This is enforced at two
  independent layers on purpose.
- No automatic verifier-error-to-LLM retry loop. `validate_script` returns
  the raw bpftrace compile error; wiring up an automatic "LLM reads the
  error and retries" loop is a natural next step once you've used this
  manually a few times and have a feel for what errors actually show up.
- No network exposure. This talks stdio only. If you want this reachable
  remotely later, that's a real auth/access-control project on its own --
  don't bolt on a port without thinking that through separately.
