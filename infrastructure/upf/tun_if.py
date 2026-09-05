# BSD 2-Clause License

# Copyright (c) 2020-2025, Supreeth Herle
# All rights reserved.

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:

# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.

# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import click
import ipaddress
import re
import subprocess
from collections.abc import Sequence


_IFNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")

"""
Usage in command line:
e.g:
$ python3 tun_if.py --tun_ifname ogstun --tun_ifmode tun --ipv4_range 192.168.100.0/24 --ipv6_range 2001:230:cafe::/48 --no_nat_ipv4_addr 172.22.0.21 --no_nat_ipv6_addr 2001:230:eafe::1
"""


def validate_ip_net(ctx, param, value):
    try:
        ip_net = ipaddress.ip_network(value)
        return ip_net
    except ValueError:
        raise click.BadParameter("Value does not represent a valid IPv4/IPv6 range")


def validate_ip(ctx, param, value):
    try:
        ip_addr = ipaddress.ip_address(value)
        return ip_addr.exploded
    except ValueError:
        raise click.BadParameter("Value does not represent a valid IPv4/IPv6 address")


def _validate_ifname(value):
    if not isinstance(value, str) or not _IFNAME_PATTERN.fullmatch(value):
        raise ValueError(
            "interface name must be 1-15 characters using only letters, "
            "digits, '.', '_' or '-'"
        )
    return value


def validate_ifname(ctx, param, value):
    try:
        return _validate_ifname(value)
    except ValueError as exc:
        raise click.BadParameter(str(exc)) from exc


@click.command()
@click.option(
    "--tun_ifname",
    required=True,
    callback=validate_ifname,
    help="TUN interface name e.g. ogstun",
)
@click.option(
    "--tun_ifmode",
    required=True,
    type=click.Choice(["tun", "tap"]),
    help="TUN interface mode e.g. tun or tap",
)
@click.option(
    "--ipv4_range",
    required=True,
    callback=validate_ip_net,
    help="UE IPv4 Address range in CIDR format e.g. 192.168.100.0/24",
)
@click.option(
    "--ipv6_range",
    required=True,
    callback=validate_ip_net,
    help="UE IPv6 Address range in CIDR format e.g. 2001:230:cafe::/48",
)
@click.option(
    "--no_nat_ipv4_addr",
    required=True,
    callback=validate_ip,
    help="Destination IPv4 address to which NATing must not be applied e.g. 172.22.0.21",
)
@click.option(
    "--no_nat_ipv6_addr",
    required=True,
    callback=validate_ip,
    help="Destination IPv6 address to which NATing must not be applied e.g. 2001:230:eafe::1",
)
@click.option(
    "--nat_rule",
    default="yes",
    help="Option specifying whether to add NATing iptables rule or not",
)
def start(
    tun_ifname,
    tun_ifmode,
    ipv4_range,
    ipv6_range,
    no_nat_ipv4_addr,
    no_nat_ipv6_addr,
    nat_rule,
):

    tun_ifname = _validate_ifname(tun_ifname)

    # Get the first IP address in the IP range and netmask prefix length
    first_ipv4_addr = next(ipv4_range.hosts(), None)
    if not first_ipv4_addr:
        raise ValueError("Invalid UE IPv4 range. Only one IP given")
    else:
        first_ipv4_addr = first_ipv4_addr.exploded
    first_ipv6_addr = next(ipv6_range.hosts(), None)
    if not first_ipv6_addr:
        raise ValueError("Invalid UE IPv6 range. Only one IP given")
    else:
        first_ipv6_addr = first_ipv6_addr.exploded

    ipv4_netmask_prefix = ipv4_range.prefixlen
    ipv6_netmask_prefix = ipv6_range.prefixlen

    # Setup the TUN/TAP interface, set IP address and setup IPtables
    execute_bash_cmd("ip", "tuntap", "add", "name", tun_ifname, "mode", tun_ifmode)
    execute_bash_cmd(
        "ip",
        "addr",
        "add",
        f"{first_ipv4_addr}/{ipv4_netmask_prefix}",
        "dev",
        tun_ifname,
    )
    execute_bash_cmd(
        "ip",
        "addr",
        "add",
        f"{first_ipv6_addr}/{ipv6_netmask_prefix}",
        "dev",
        tun_ifname,
    )
    execute_bash_cmd("ip", "link", "set", tun_ifname, "mtu", "1450")
    execute_bash_cmd("ip", "link", "set", tun_ifname, "up")
    if nat_rule == "yes":
        ipv4_rule = (
            f"-A POSTROUTING -s {ipv4_range.with_prefixlen} ! -o {tun_ifname} "
            f"! -d {no_nat_ipv4_addr} -j MASQUERADE"
        )
        _ensure_rule(
            "iptables-save",
            ipv4_rule,
            (
                "iptables",
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                ipv4_range.with_prefixlen,
                "!",
                "-o",
                tun_ifname,
                "!",
                "-d",
                no_nat_ipv4_addr,
                "-j",
                "MASQUERADE",
            ),
        )
        ipv6_rule = (
            f"-A POSTROUTING -s {ipv6_range.with_prefixlen} ! -o {tun_ifname} "
            f"! -d {no_nat_ipv6_addr} -j MASQUERADE"
        )
        _ensure_rule(
            "ip6tables-save",
            ipv6_rule,
            (
                "ip6tables",
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                ipv6_range.with_prefixlen,
                "!",
                "-o",
                tun_ifname,
                "!",
                "-d",
                no_nat_ipv6_addr,
                "-j",
                "MASQUERADE",
            ),
        )
        _ensure_rule(
            "iptables-save",
            f"-A INPUT -i {tun_ifname} -j ACCEPT",
            ("iptables", "-A", "INPUT", "-i", tun_ifname, "-j", "ACCEPT"),
        )
        _ensure_rule(
            "ip6tables-save",
            f"-A INPUT -i {tun_ifname} -j ACCEPT",
            ("ip6tables", "-A", "INPUT", "-i", tun_ifname, "-j", "ACCEPT"),
        )


def execute_bash_cmd(*command: str):
    """Run one system command without invoking a shell."""
    return subprocess.run(command, stdout=subprocess.PIPE, shell=False)


def _ensure_rule(
    save_command: str,
    rule: str,
    add_command: Sequence[str],
) -> None:
    result = subprocess.run(
        [save_command],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
    )
    if result.returncode != 0 or rule not in result.stdout:
        execute_bash_cmd(*add_command)


if __name__ == "__main__":
    start()
