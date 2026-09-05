from __future__ import annotations

import ipaddress
import subprocess
from unittest.mock import patch

import click
import pytest

from infrastructure.upf import tun_if


def test_validate_ifname_rejects_shell_metacharacters() -> None:
    with pytest.raises(click.BadParameter):
        tun_if.validate_ifname(None, None, "ogstun; touch /tmp/pwned")


def test_start_runs_network_commands_without_a_shell() -> None:
    calls: list[tuple[tuple[str, ...], dict]] = []

    def fake_run(command, **kwargs):  # noqa: ANN001
        calls.append((tuple(command), kwargs))
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    start_callback = tun_if.start.callback
    assert start_callback is not None
    with patch.object(tun_if.subprocess, "run", side_effect=fake_run):
        start_callback(
            "ogstun",
            "tun",
            ipaddress.ip_network("10.20.20.0/24"),
            ipaddress.ip_network("2001:db8:20::/64"),
            "172.22.0.21",
            "2001:db8::21",
            "yes",
        )

    assert calls
    assert all(kwargs["shell"] is False for _command, kwargs in calls)
    assert all(isinstance(command, tuple) for command, _kwargs in calls)
    assert calls[0][0] == ("ip", "tuntap", "add", "name", "ogstun", "mode", "tun")
    assert ("iptables", "-t", "nat", "-A", "POSTROUTING") == calls[6][0][:5]


def test_start_rejects_invalid_ifname_before_running_commands() -> None:
    start_callback = tun_if.start.callback
    assert start_callback is not None
    with patch.object(tun_if.subprocess, "run") as run:
        with pytest.raises(ValueError):
            start_callback(
                "ogstun;bad",
                "tun",
                ipaddress.ip_network("10.20.20.0/24"),
                ipaddress.ip_network("2001:db8:20::/64"),
                "172.22.0.21",
                "2001:db8::21",
                "no",
            )

    run.assert_not_called()
