import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ebpf_mcp_tracer.safety import validate_script, extract_probe_headers


def test_allowed_tracepoint_passes():
    script = """
    tracepoint:syscalls:sys_enter_openat {
        printf("open: %s\\n", str(args->filename));
    }
    """
    assert validate_script(script) == []


def test_allowed_kprobe_passes():
    script = """
    kprobe:vfs_open {
        printf("vfs_open pid=%d\\n", pid);
    }
    """
    assert validate_script(script) == []


def test_unlisted_kprobe_is_blocked():
    script = """
    kprobe:do_exit {
        printf("exit pid=%d\\n", pid);
    }
    """
    violations = validate_script(script)
    assert len(violations) == 1
    assert "do_exit" in violations[0]


def test_wildcard_kprobe_is_blocked():
    script = """
    kprobe:tcp_* {
        printf("tcp event\\n");
    }
    """
    violations = validate_script(script)
    assert any("tcp_*" in v for v in violations)


def test_system_builtin_is_blocked():
    script = """
    BEGIN {
        system("rm -rf /tmp/whatever");
    }
    """
    violations = validate_script(script)
    assert any("system" in v for v in violations)


def test_override_builtin_is_blocked():
    script = """
    kprobe:vfs_open {
        override(-1);
    }
    """
    violations = validate_script(script)
    assert any("override" in v for v in violations)


def test_empty_script_is_blocked():
    assert validate_script("   ") != []


def test_no_probes_is_blocked():
    assert validate_script("// just a comment, no probes") != []


def test_multi_probe_line():
    headers = extract_probe_headers(
        "tracepoint:syscalls:sys_enter_open,\ntracepoint:syscalls:sys_enter_openat {\n    1;\n}"
    )
    assert "tracepoint:syscalls:sys_enter_open" in headers
    assert "tracepoint:syscalls:sys_enter_openat" in headers


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
