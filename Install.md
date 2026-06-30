# Installation & Setup Guide - eBPF MCP Tracer

This guide covers everything you need to install, configure, and troubleshoot the eBPF MCP Tracer.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [MCP Client Configuration](#-mcp-client-configuration)
- [Troubleshooting](#-troubleshooting)
- [Testing](#-testing)
- [Security Notes](#-security-notes)
- [Additional Resources](#-additional-resources)

---

## Prerequisites

- **Operating System**: Ubuntu 20.04+ (ARM64/aarch64 tested)
- **Kernel**: Version 5.8+ (for BPF capabilities support)
- **Python**: 3.8 or higher
- **Permissions**: Root or sudo access

---

## Quick Start

### 1. Install Dependencies

```bash
# Update system
sudo apt update

# Install Python venv and pip
sudo apt install python3-venv python3-pip build-essential -y

# Install eBPF development tools
sudo apt install linux-headers-$(uname -r) clang llvm libbpf-dev pkg-config bpftrace -y
```

### 2. Clone and Setup Virtual Environment

```bash
# Clone the repository
git clone git@github.com:blackdragoon26/ebpf-mcp-tracer.git
cd ebpf-mcp-tracer

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

### 3. Grant Capabilities (Kernel 5.8+)

Instead of running as root, grant specific capabilities to Python:

```bash
# Grant capabilities to Python binary
sudo setcap cap_bpf,cap_perfmon,cap_sys_resource+ep $(readlink -f venv/bin/python3)

# Grant capabilities to bpftrace (required for listing probes)
sudo setcap cap_bpf,cap_perfmon,cap_sys_admin+ep $(which bpftrace)

# Verify capabilities are set
getcap $(which bpftrace)
# Should output: /usr/bin/bpftrace cap_sys_admin,cap_perfmon,cap_bpf=ep
```

> **Important:** If you still get "Permission denied" errors when listing probes, it's because capabilities don't bypass file permissions on `/sys/kernel/tracing/`. You have two options:

**Option A: Run MCP server with sudo (Recommended for dev VMs)**
```bash
# Allow passwordless sudo for your user (optional but convenient)
echo "youruser ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/youruser

# Run server with sudo
sudo PYTHONPATH=src python3 -m ebpf_mcp_tracer.server
```

**Option B: Fix tracefs permissions**
```bash
# Make tracing filesystem readable (less secure, dev only)
sudo chmod -R a+r /sys/kernel/tracing/
```

### 4. Running the Server

```bash
# Method 1: Run as module (correct way)
cd ebpf-mcp-tracer
PYTHONPATH=src python3 -m ebpf_mcp_tracer.server

# Method 2: Run with sudo (if you need full tracing access)
sudo PYTHONPATH=src python3 -m ebpf_mcp_tracer.server

# Method 3: For development/testing
python3 -m mcp dev src/ebpf_mcp_tracer/server.py
```

> **Common Error:** `ImportError: attempted relative import with no known parent package`
> 
> **Fix:** Always use `PYTHONPATH=src python3 -m ebpf_mcp_tracer.server` instead of `python3 src/ebpf_mcp_tracer/server.py`

---

## MCP Client Configuration

### Cursor (Recommended - Native MCP Support)

1. **Download Cursor**: https://cursor.sh

2. **Configure MCP Server**:
   - Open Cursor Settings (`Cmd + ,`)
   - Search for "MCP"
   - Click "Add New MCP Server"
   - Paste this configuration:

```json
{
  "mcpServers": {
    "ebpf-tracer": {
      "command": "ssh",
      "args": [
        "youruser@vm-ip-address",
        "sudo PYTHONPATH=/path/to/ebpf-mcp-tracer/src /path/to/ebpf-mcp-tracer/venv/bin/python3 -m ebpf_mcp_tracer.server"
      ]
    }
  }
}
```

3. **Setup Passwordless SSH** (Required for automatic connection):

```bash
# On your Mac/local machine
ssh-keygen -t ed25519 -C "your_email@example.com"
ssh-copy-id youruser@vm-ip-address

# Test connection
ssh youruser@vm-ip-address  # Should connect without password
```

4. **Restart Cursor** and test by asking: *"List the live eBPF probes available on my kernel"*

### Continue for VS Code

> **Note:** Continue v2.0 has limited MCP support. We recommend using Cursor instead. If you must use Continue:

1. Edit `~/.continue/config.yaml`:

```yaml
name: Main Config
version: 1.0.0
schema: v1
models:
  - name: Your Model
    provider: openai  # or anthropic, gemini, etc.
    # ... your model config
experimental:
  modelContextProtocol:
    servers:
      - name: ebpf-tracer
        command: ssh
        args:
          - youruser@vm-ip-address
          - "sudo PYTHONPATH=/path/to/src /path/to/venv/bin/python3 -m ebpf_mcp_tracer.server"
```

2. Reload Continue: `Cmd + Shift + P` → "Continue: Reload Config"

---

## Troubleshooting

### "Permission denied" when reading `/sys/kernel/tracing/available_events`

**Cause:** File permissions block access even with capabilities set.

**Solutions:**
1. Run server with `sudo` (recommended for dev)
2. Or fix permissions: `sudo chmod -R a+r /sys/kernel/tracing/`
3. Or add user to appropriate groups (varies by distro)

### "bpftrace not found" or "command not found"

**Cause:** bpftrace not installed or not in PATH.

**Fix:**
```bash
sudo apt install bpftrace
which bpftrace  # Verify installation
```

### MCP server won't connect from Cursor/Continue

**Check:**
1. SSH works without password: `ssh youruser@vm-ip`
2. Server starts correctly: Test manually with `PYTHONPATH=src python3 -m ebpf_mcp_tracer.server`
3. Paths in MCP config are absolute and correct
4. Restart Cursor/Continue after config changes

### "No module named mcp.__main__"

**Cause:** Trying to run `python3 -m mcp dev ...` which isn't supported.

**Fix:** Use `PYTHONPATH=src python3 -m ebpf_mcp_tracer.server` instead.

### Kernel version too old (< 5.8)

**Cause:** Capabilities like `cap_bpf` and `cap_perfmon` were added in kernel 5.8.

**Check:** `uname -r`

**Fix:** Upgrade kernel or run server as root (not recommended for production).

---

## Testing

### Run Safety Tests

```bash
pip install pytest
PYTHONPATH=src python3 -m pytest tests/test_safety.py -v
```

### Test Server Manually

```bash
# Start server
PYTHONPATH=src python3 -m ebpf_mcp_tracer.server

# In another terminal, send test JSON
echo '{"jsonrpc":"2.0","id":1,"method":"list_probes","params":{"pattern":"tracepoint:syscalls:*"}}' | \
  PYTHONPATH=src python3 -m ebpf_mcp_tracer.server
```

### Verify Capabilities

```bash
# Check Python has capabilities
getcap $(readlink -f venv/bin/python3)

# Check bpftrace has capabilities
getcap $(which bpftrace)

# Test bpftrace access
sudo bpftrace -l 'tracepoint:syscalls:*' | head -5
```

---

## Security Notes

1. **Running as root**: The MCP server needs elevated privileges to load BPF programs. For development VMs, running with `sudo` is acceptable. For production, use fine-grained capabilities.

2. **Allowlist**: The `ALLOWED_PROBE_PATTERNS` in `safety.py` prevents dangerous probes. Never add wildcards like `kprobe:*` - always specify exact functions.

3. **SSH Keys**: Use password-protected SSH keys for production. The passwordless setup shown here is for development convenience only.

4. **Network Access**: The MCP server communicates over stdio via SSH. Ensure your VM firewall allows SSH (port 22) only from trusted IPs.

---

## Additional Resources

- [bpftrace Documentation](https://github.com/iovisor/bpftrace)
- [MCP Protocol Spec](https://modelcontextprotocol.io)
- [Cursor MCP Docs](https://docs.cursor.com/mcp)
- [Linux Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)

---

## Contributing

Found a bug or want to add a feature?

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Run tests: `PYTHONPATH=src python3 -m pytest tests/`
4. Commit: `git commit -m "Add amazing feature"`
5. Push: `git push origin feature/amazing-feature`
6. Open a Pull Request

---

## Acknowledgments

- Built with the [MCP SDK](https://github.com/modelcontextprotocol)
- eBPF tracing powered by [bpftrace](https://github.com/iovisor/bpftrace)
- Special thanks to the Linux kernel community for eBPF

---

**Last Updated:** June 2026
