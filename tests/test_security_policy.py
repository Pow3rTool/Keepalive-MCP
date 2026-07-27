"""Characterization tests for the command and output safety boundary."""
import pytest

import server


@pytest.mark.parametrize(
    "command",
    [
        "show crypto key mypubkey rsa",
        "show key chain",
        "more flash:/private-config",
        "more private-config.text",
        "type /etc/passwd",
        "dir nvram:",
        "show snmp user keys",
        "show interfaces | redirect tftp://192.0.2.1/output",
    ],
)
def test_raw_key_and_file_reads_are_always_blocked(command, monkeypatch):
    monkeypatch.setattr(server, "ALLOW_CONFIG_READ", True)
    assert "refused:" in server._blocked_read(command)


@pytest.mark.parametrize(
    "command",
    [
        "show running-config",
        "show startup-config",
        "show tech-support",
    ],
)
def test_dense_config_reads_are_blocked_by_default(command, monkeypatch):
    monkeypatch.setattr(server, "ALLOW_CONFIG_READ", False)
    assert "full-config" in server._blocked_read(command)


def test_operator_can_enable_config_reads_without_enabling_raw_files(monkeypatch):
    monkeypatch.setattr(server, "ALLOW_CONFIG_READ", True)
    assert server._blocked_read("show running-config") == ""
    assert "refused:" in server._blocked_read("more flash:/private-config")


@pytest.mark.parametrize(
    "command",
    [
        "",
        "show clock\nconfigure terminal",
        "show clock; reload",
        "showcase dangerous-prefix",
        "configure terminal",
        "show interfaces | save /var/tmp/interfaces",
    ],
)
def test_read_command_validator_refuses_injection_and_non_read_verbs(command):
    assert server._read_command_error(command)


@pytest.mark.parametrize(
    "command",
    [
        "show clock",
        "show interfaces | include up",
        "ping 192.0.2.1",
        "traceroute 192.0.2.1",
        "changeto context customer-a",
    ],
)
def test_read_command_validator_accepts_one_safe_command(command):
    assert server._read_command_error(command) == ""


@pytest.mark.parametrize(
    ("source", "secret"),
    [
        ("enable secret 9 swordfish", "swordfish"),
        ("snmp-server community public RO", "public"),
        (" key-string hunter2", "hunter2"),
        ("username admin secret 5 ciphertext", "ciphertext"),
        ("crypto isakmp key pskvalue address 10.0.0.1", "pskvalue"),
        ("radius server ISE key 7 radiussecret", "radiussecret"),
    ],
)
def test_secret_values_are_redacted(source, secret):
    redacted = server._redact_secrets(source)
    assert secret not in redacted
    assert "«redacted»" in redacted


def test_redaction_preserves_safe_lines_and_all_result_surfaces():
    safe = "interface Loopback0\n description harmless"
    assert server._redact_secrets(safe) == safe

    result = server._redact_result({
        "config_diff": "enable secret 9 swordfish",
        "device_said": "snmp-server community public",
        "commit_output": "key-string hunter2",
        "actual_net_change": {
            "added": ["username admin secret ciphertext"],
            "removed": ["description safe"],
        },
    })
    rendered = repr(result)
    for secret in ("swordfish", "public", "hunter2", "ciphertext"):
        assert secret not in rendered
    assert "description safe" in rendered


def test_diff_and_verification_ignore_volatile_lines():
    before = "Building configuration...\ninterface Loopback0\n description old\n"
    after = "Current configuration : 42 bytes\ninterface Loopback0\n description new\n"

    diff, added, removed = server._diff(before, after)
    assert "Building configuration" not in diff
    assert "Current configuration" not in diff
    assert "description new" in added
    assert "description old" in removed
    assert server._verify(["interface Loopback0", "description new"], after)["match"]
