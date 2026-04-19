import json
import os
import platform
import re
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Final

from volte_mutation_fuzzer.infra.core import setup_ue_route
from volte_mutation_fuzzer.sender.contracts import SendArtifact, TargetEndpoint
from volte_mutation_fuzzer.sip.common import NameAddress, SIPURI, ViaHeader
from volte_mutation_fuzzer.sip.render import PacketModel, render_packet_bytes

_CRLF: Final[str] = "\r\n"
_DEFAULT_REAL_UE_IMS_SUBNET: Final[str] = "10.20.20.0/24"
_DEFAULT_REAL_UE_UPF_IP: Final[str] = "172.22.0.8"
_DEFAULT_REAL_UE_PCSCF_IP: Final[str] = "172.22.0.21"
_DEFAULT_SCSCF_CONTAINER: Final[str] = "scscf"
_DEFAULT_PCSCF_CONTAINER: Final[str] = "pcscf"
_DEFAULT_MYSQL_CONTAINER: Final[str] = "mysql"
_DEFAULT_SCSCF_DB_USER: Final[str] = "scscf"
_DEFAULT_SCSCF_DB_PASS: Final[str] = "heslo"
_DEFAULT_SCSCF_DB_NAME: Final[str] = "scscf"
_DEFAULT_PCSCF_LOG_TAIL: Final[int] = 500
_PCSCF_TERM_UE_PORT_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"Term UE connection information\s*:\s*IP is ([\d.]+) and Port is (\d+)"
)
_XFRM_DPORT_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"proto esp\s.*?src\s+\S+\s+dst\s+([\d.]+).*?\n.*?sport\s+(\d+)\s+dport\s+(\d+)",
    re.DOTALL,
)
_KAMCTL_CONTACT_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"Contact:\s*<sip:[^@]+@([\d.]+):(\d+)"
)
_PCSCF_LOG_CONTACT_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"Contact header:\s*<sip:(\d+)@([\d.]+):(\d+)>"
)
_VIA_SENT_BY_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^(SIP/2\.0/[^\s]+\s+)([^;\s]+)(.*)$",
    re.IGNORECASE,
)
_CONTACT_HOSTPORT_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(<\s*sips?:[^@<>\s]+@)([^;>\s]+)",
    re.IGNORECASE,
)

# MSISDN → UE IP mapping for auto-resolution
_DEFAULT_MSISDN_TO_IP: Final[dict[str, str]] = {
    "111111": "10.20.20.8",  # Samsung A31
    "222222": "10.20.20.9",  # Test MO softphone
}


def resolve_ue_ip_from_msisdn(
    msisdn: str, *, env: dict[str, str] | None = None
) -> str:
    """Resolve UE IP address from MSISDN.

    Args:
        msisdn: Target MSISDN (e.g., "111111")
        env: Environment variables for mapping overrides

    Returns:
        UE IP address (e.g., "10.20.20.8")

    Raises:
        ValueError: If MSISDN is not found in mapping table
    """
    if env is None:
        env = os.environ

    # Check for environment variable override: VMF_MSISDN_TO_IP_<msisdn>
    env_key = f"VMF_MSISDN_TO_IP_{msisdn}"
    if env_key in env:
        return env[env_key]

    # Check default mapping table
    if msisdn in _DEFAULT_MSISDN_TO_IP:
        return _DEFAULT_MSISDN_TO_IP[msisdn]

    raise ValueError(
        f"Unknown MSISDN {msisdn!r}. Available: {list(_DEFAULT_MSISDN_TO_IP.keys())}. "
        f"Override with environment variable {env_key}=<ip>"
    )


class RealUEDirectError(RuntimeError):
    """Base error for real-ue-direct preparation failures."""

    def __init__(
        self,
        message: str,
        *,
        observer_events: tuple[str, ...] = (),
        resolved_target: TargetEndpoint | None = None,
    ) -> None:
        super().__init__(message)
        self.observer_events = observer_events
        self.resolved_target = resolved_target


class RealUEDirectResolutionError(RealUEDirectError):
    """Raised when a real UE MSISDN cannot be resolved to a contact endpoint."""


class RealUEDirectRouteError(RealUEDirectError):
    """Raised when the host cannot route traffic toward the real UE target."""


@dataclass(frozen=True)
class ResolvedNativeIPsecSession:
    ue_ip: str
    pcscf_ip: str
    port_map: dict[int, int]
    observer_events: tuple[str, ...]

    def pcscf_port_for(self, ue_port: int) -> int:
        try:
            return self.port_map[ue_port]
        except KeyError as exc:
            raise RealUEDirectResolutionError(
                f"unknown UE protected port {ue_port} for native IPsec session "
                f"({self.ue_ip} -> {self.pcscf_ip}); known ports: "
                f"{sorted(self.port_map)}"
            ) from exc


@dataclass(frozen=True)
class UEContact:
    msisdn: str
    host: str
    port: int
    source: str
    impi: str | None = None


@dataclass(frozen=True)
class ResolvedRealUETarget:
    host: str
    port: int
    label: str | None
    observer_events: tuple[str, ...]
    impi: str | None = None


@dataclass(frozen=True)
class RouteCheckResult:
    ok: bool
    detail: str


class RealUEDirectResolver:
    """Resolves capstone-style real UE targets from static or lab-backed sources."""

    def __init__(self, env: dict[str, str] | None = None) -> None:
        source = os.environ if env is None else env
        self._env = source
        self.scscf_container = source.get(
            "VMF_REAL_UE_SCSCF_CONTAINER", _DEFAULT_SCSCF_CONTAINER
        )
        self.pcscf_container = source.get(
            "VMF_REAL_UE_PCSCF_CONTAINER", _DEFAULT_PCSCF_CONTAINER
        )
        self.mysql_container = source.get(
            "VMF_REAL_UE_MYSQL_CONTAINER", _DEFAULT_MYSQL_CONTAINER
        )
        self.scscf_db_user = source.get("VMF_REAL_UE_SCSCF_DB_USER", _DEFAULT_SCSCF_DB_USER)
        self.scscf_db_pass = source.get("VMF_REAL_UE_SCSCF_DB_PASS", _DEFAULT_SCSCF_DB_PASS)
        self.scscf_db_name = source.get("VMF_REAL_UE_SCSCF_DB_NAME", _DEFAULT_SCSCF_DB_NAME)
        self.pyhss_url = _normalize_optional_text(source.get("VMF_REAL_UE_PYHSS_URL"))
        raw_log_tail = source.get("VMF_REAL_UE_PCSCF_LOG_TAIL")
        try:
            self.pcscf_log_tail = (
                int(raw_log_tail)
                if raw_log_tail is not None
                else _DEFAULT_PCSCF_LOG_TAIL
            )
        except ValueError:
            self.pcscf_log_tail = _DEFAULT_PCSCF_LOG_TAIL

    def resolve(
        self, target: TargetEndpoint, *, impi: str | None = None,
    ) -> ResolvedRealUETarget:
        if target.host is not None:
            assert target.port is not None
            label = target.label or target.host
            return ResolvedRealUETarget(
                host=target.host,
                port=target.port,
                label=label,
                observer_events=(f"resolver:static:{target.host}:{target.port}",),
            )

        assert target.msisdn is not None
        msisdn = target.msisdn
        resolved_port = target.port

        contact = self._lookup_via_kamctl(msisdn, container=self.scscf_container)
        if contact is None and self.pcscf_container != self.scscf_container:
            contact = self._lookup_via_kamctl(msisdn, container=self.pcscf_container)
        if contact is None:
            contact = self._lookup_via_scscf_mysql(msisdn)
        if contact is None:
            contact = self._lookup_via_pcscf_logs(msisdn)
        if contact is None:
            contact = self._lookup_via_pcscf_options_ping(msisdn, impi=impi)
        if contact is None:
            contact = self._lookup_via_xfrm_state(msisdn)
        if contact is None:
            raise RealUEDirectResolutionError(
                f"real-ue-direct target msisdn {msisdn} could not be resolved via "
                "docker Kamailio, P-CSCF log, or xfrm state backends"
            )

        final_port = resolved_port or contact.port
        label = target.label or f"msisdn:{msisdn}"
        return ResolvedRealUETarget(
            host=contact.host,
            port=final_port,
            label=label,
            observer_events=(
                f"resolver:{contact.source}:{msisdn}->{contact.host}:{final_port}",
            ),
            impi=contact.impi,
        )

    def _lookup_via_kamctl(self, msisdn: str, *, container: str) -> UEContact | None:
        for command in (
            ["docker", "exec", container, "kamctl", "ul", "show", f"sip:{msisdn}@*"],
            ["docker", "exec", container, "kamctl", "ul", "show"],
        ):
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=10.0,
                    check=False,
                )
            except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
                return None
            if result.returncode != 0 or not result.stdout:
                continue
            contact = self._parse_kamctl_output(msisdn, result.stdout)
            if contact is not None:
                return UEContact(
                    msisdn=msisdn,
                    host=contact.host,
                    port=contact.port,
                    source=f"{container}-kamctl",
                )
        return None

    def _lookup_via_scscf_mysql(self, msisdn: str) -> UEContact | None:
        """Query S-CSCF Kamailio location table via docker exec mysql — capstone-style fallback."""
        if not msisdn.isdigit():
            return None
        query = (
            f"SELECT contact FROM location "
            f"WHERE username LIKE '%{msisdn}%' "
            f"ORDER BY expires DESC LIMIT 1;"
        )
        try:
            result = subprocess.run(
                [
                    "docker",
                    "exec",
                    self.mysql_container,
                    "mysql",
                    "-u",
                    self.scscf_db_user,
                    f"-p{self.scscf_db_pass}",
                    self.scscf_db_name,
                    "-se",
                    query,
                ],
                capture_output=True,
                text=True,
                timeout=10.0,
                check=False,
            )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            return None

        if result.returncode != 0 or not result.stdout.strip():
            return None

        contact_uri = result.stdout.strip().splitlines()[-1].strip()
        match = _KAMCTL_CONTACT_PATTERN.search(contact_uri)
        if match is not None:
            return UEContact(
                msisdn=msisdn,
                host=match.group(1),
                port=int(match.group(2)),
                source="scscf-mysql",
            )
        return None

    def _lookup_via_pcscf_logs(self, msisdn: str) -> UEContact | None:
        try:
            result = subprocess.run(
                [
                    "docker",
                    "logs",
                    self.pcscf_container,
                    "--tail",
                    str(self.pcscf_log_tail),
                ],
                capture_output=True,
                text=True,
                timeout=15.0,
                check=False,
            )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            return None

        if result.returncode != 0:
            return None

        imsi_for_msisdn = self._lookup_imsi_from_pyhss(msisdn)
        lines = (result.stdout + result.stderr).splitlines()
        for line in reversed(lines):
            match = _PCSCF_LOG_CONTACT_PATTERN.search(line)
            if match is None:
                continue
            imsi = match.group(1)
            host = match.group(2)
            port = int(match.group(3))
            if imsi_for_msisdn is not None:
                if imsi != imsi_for_msisdn:
                    continue
            elif msisdn not in imsi and not imsi.endswith(msisdn):
                continue
            return UEContact(
                msisdn=msisdn,
                host=host,
                port=port,
                source="pcscf-log",
            )
        return None

    def _lookup_via_pcscf_options_ping(
        self, msisdn: str, *, impi: str | None = None,
    ) -> UEContact | None:
        """Parse pcscf logs for OPTIONS keepalive pings that contain IMPI→IP mapping.

        Matches lines like:
            OPTIONS to sip:001010000123512@10.20.20.2:8200 via ...
        """
        try:
            result = subprocess.run(
                ["docker", "logs", self.pcscf_container, "--tail", str(self.pcscf_log_tail)],
                capture_output=True, text=True, timeout=15.0, check=False,
            )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            return None
        if result.returncode != 0:
            return None

        # Pattern: OPTIONS to sip:<impi>@<ip>:<port>
        pattern = re.compile(r"OPTIONS to sip:(\S+?)@([\d.]+):(\d+)")
        lines = (result.stdout + result.stderr).splitlines()
        last_seen: UEContact | None = None
        for line in reversed(lines):
            match = pattern.search(line)
            if match is None:
                continue
            log_impi = match.group(1)
            host = match.group(2)
            port = int(match.group(3))
            contact = UEContact(msisdn=msisdn, host=host, port=port, source="pcscf-options-ping", impi=log_impi)
            # Exact IMPI match — best
            if impi is not None and log_impi == impi:
                return contact
            # MSISDN substring match
            if msisdn in log_impi or log_impi.endswith(msisdn):
                return contact
            # Remember most recent entry as fallback (single-UE mode)
            if last_seen is None:
                last_seen = contact
        # No MSISDN/IMPI match — return most recent entry if available
        return last_seen

    def _lookup_via_xfrm_state(self, msisdn: str) -> UEContact | None:
        """Parse xfrm state for UE IP — fallback when no MSISDN-level match is possible.

        Returns the first non-P-CSCF IP found in IPsec SAs. Only useful in
        single-UE environments.
        """
        pcscf_ip = os.environ.get("VMF_REAL_UE_PCSCF_IP", "172.22.0.21")
        try:
            result = subprocess.run(
                ["docker", "exec", self.pcscf_container, "ip", "xfrm", "state"],
                capture_output=True, text=True, timeout=10.0, check=False,
            )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            return None
        if result.returncode != 0:
            return None

        # Find "src <ue_ip> dst <pcscf_ip>" lines → extract UE IP + sport
        pattern = re.compile(
            r"sel src ([\d.]+)/\d+ dst " + re.escape(pcscf_ip) + r"/\d+ sport (\d+) dport (\d+)"
        )
        for match in pattern.finditer(result.stdout):
            ue_ip = match.group(1)
            ue_port = int(match.group(2))
            if ue_ip != pcscf_ip:
                return UEContact(msisdn=msisdn, host=ue_ip, port=ue_port, source="xfrm-state")
        return None

    def _lookup_imsi_from_pyhss(self, msisdn: str) -> str | None:
        if self.pyhss_url is None:
            return None
        url = f"{self.pyhss_url.rstrip('/')}/ims_subscriber/list?page=0&page_size=200"
        request = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=5.0) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, ValueError):
            return None

        if not isinstance(payload, list):
            return None
        for item in payload:
            if not isinstance(item, dict):
                continue
            if item.get("msisdn") == msisdn:
                imsi = item.get("imsi")
                if isinstance(imsi, str) and imsi.strip():
                    return imsi.strip()
        return None

    def resolve_protected_ports(self, msisdn: str) -> tuple[int, int]:
        """Return ``(port_pc, port_ps)`` for the UE identified by *msisdn*.

        The requested MSISDN is resolved to a UE IP first, then both log-derived
        and xfrm-derived candidates are filtered to that UE before selection.
        """
        return resolve_ue_protected_ports(
            msisdn=msisdn,
            pcscf_container=self.pcscf_container,
            env=self._env,
        )

    def _parse_kamctl_output(self, msisdn: str, output: str) -> UEContact | None:
        lines = output.splitlines()
        has_aor_sections = any(line.startswith("AOR:") for line in lines)

        if not has_aor_sections:
            # Single-AOR response (e.g. kamctl ul show sip:111111@*) — safe to grab first match
            direct_match = _KAMCTL_CONTACT_PATTERN.search(output)
            if direct_match is not None:
                return UEContact(
                    msisdn=msisdn,
                    host=direct_match.group(1),
                    port=int(direct_match.group(2)),
                    source="kamctl",
                )
            return None

        # Multi-AOR response (kamctl ul show) — must filter by MSISDN to avoid wrong UE contact
        current_aor_matches = False
        for line in lines:
            if line.startswith("AOR:"):
                current_aor_matches = msisdn in line
                continue
            if not current_aor_matches:
                continue
            match = _KAMCTL_CONTACT_PATTERN.search(line)
            if match is not None:
                return UEContact(
                    msisdn=msisdn,
                    host=match.group(1),
                    port=int(match.group(2)),
                    source="kamctl",
                )
        return None


def resolve_ue_protected_ports(
    *,
    msisdn: str,
    pcscf_container: str = _DEFAULT_PCSCF_CONTAINER,
    env: dict[str, str] | None = None,
) -> tuple[int, int]:
    """Return ``(port_pc, port_ps)`` for *msisdn* by querying the P-CSCF container.

    Strategy:
    1. Resolve the UE IP for *msisdn* and use it to filter candidates.
    2. Parse the last matching ``Term UE connection`` log line from the P-CSCF container.
    3. Fallback: parse ``ip xfrm state`` output for matching UE port pairs.
    4. Raise ``RealUEDirectResolutionError`` if neither succeeds.

    ``port_ps`` is assumed to be ``port_pc + 1`` when derived from logs.
    """
    requested_ue_ip: str | None = None
    try:
        requested_ue_ip = resolve_ue_ip_from_msisdn(msisdn, env=env)
    except ValueError:
        requested_ue_ip = None
    source = os.environ if env is None else env
    pcscf_ip = source.get("VMF_REAL_UE_PCSCF_IP", _DEFAULT_REAL_UE_PCSCF_IP)

    # Strategy 1: P-CSCF logs
    try:
        result = subprocess.run(
            ["docker", "logs", pcscf_container, "--since", "5m"],
            capture_output=True,
            text=True,
            timeout=15.0,
            check=False,
        )
        combined = (result.stdout or "") + (result.stderr or "")
        matches = list(_PCSCF_TERM_UE_PORT_PATTERN.finditer(combined))
        if matches:
            if requested_ue_ip is not None:
                matching_ports = [
                    int(match.group(2))
                    for match in matches
                    if match.group(1) == requested_ue_ip
                ]
                if matching_ports:
                    port_pc = matching_ports[-1]
                    return port_pc, port_pc + 1
            else:
                port_pc = int(matches[-1].group(2))
                return port_pc, port_pc + 1
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        pass

    # Strategy 2: ip xfrm state inside container
    try:
        result = subprocess.run(
            ["docker", "exec", pcscf_container, "ip", "xfrm", "state"],
            capture_output=True,
            text=True,
            timeout=10.0,
            check=False,
        )
        if result.returncode == 0 and result.stdout:
            lines = result.stdout.splitlines()
            current_src: str | None = None
            current_dst: str | None = None
            # UE→pcscf SA의 sport들: 하나는 port_pc, 다른 하나는 port_ps.
            # 관례상 min = port_pc, port_ps = port_pc + 1.
            ue_sports: list[int] = []
            for line in lines:
                stripped = line.strip()
                # Track SA direction: "src X dst Y" header line
                if stripped.startswith("src ") and " dst " in stripped:
                    parts = stripped.split()
                    if len(parts) >= 4:
                        current_src = parts[1]
                        current_dst = parts[3]
                # "sel src .../32 dst .../32 sport N dport M" — starts with "sel"
                if stripped.startswith("sel ") and "sport" in stripped and "dport" in stripped:
                    parts = stripped.split()
                    s: int | None = None
                    for idx, part in enumerate(parts):
                        if part == "sport" and idx + 1 < len(parts):
                            try:
                                s = int(parts[idx + 1])
                            except ValueError:
                                pass
                    # UE→pcscf 방향: current_src가 UE IP (10.20.20.x)
                    if (
                        current_src is not None
                        and (requested_ue_ip is None or current_src == requested_ue_ip)
                        and (current_dst is None or current_dst == pcscf_ip)
                        and s is not None
                        and s > 1024
                    ):
                        ue_sports.append(s)
            if ue_sports:
                port_pc = min(ue_sports)
                return port_pc, port_pc + 1
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        pass

    raise RealUEDirectResolutionError(
        f"could not resolve protected ports for UE via container {pcscf_container!r}. "
        "Ensure the UE is registered and logs are available."
    )


def resolve_native_ipsec_session(
    *,
    ue_ip: str,
    pcscf_container: str = _DEFAULT_PCSCF_CONTAINER,
    env: dict[str, str] | None = None,
) -> ResolvedNativeIPsecSession:
    source = os.environ if env is None else env
    pcscf_ip = source.get("VMF_REAL_UE_PCSCF_IP", _DEFAULT_REAL_UE_PCSCF_IP)

    try:
        result = subprocess.run(
            ["docker", "exec", pcscf_container, "ip", "xfrm", "state"],
            capture_output=True,
            text=True,
            timeout=10.0,
            check=False,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        raise RealUEDirectResolutionError(
            f"native IPsec xfrm query failed for container {pcscf_container!r}: {exc}"
        ) from exc

    if result.returncode != 0:
        error = result.stderr.strip() or result.stdout.strip() or "unknown error"
        raise RealUEDirectResolutionError(
            f"native IPsec xfrm query failed for container {pcscf_container!r}: {error}"
        )

    stdout = result.stdout or ""
    if not stdout.strip():
        raise RealUEDirectResolutionError(
            f"native IPsec xfrm query returned no output for container {pcscf_container!r}"
        )

    port_map: dict[int, int] = {}
    current_src: str | None = None
    current_dst: str | None = None

    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("src ") and " dst " in line:
            parts = line.split()
            if len(parts) >= 4:
                current_src = parts[1]
                current_dst = parts[3]
            else:
                current_src = None
                current_dst = None
            continue
        if not line.startswith("sel "):
            continue
        if current_src != pcscf_ip or current_dst != ue_ip:
            continue

        sport_match = re.search(r"\bsport\s+(\d+)\b", line)
        dport_match = re.search(r"\bdport\s+(\d+)\b", line)
        if sport_match is None or dport_match is None:
            continue
        sport = int(sport_match.group(1))
        dport = int(dport_match.group(1))
        port_map[dport] = sport

    if not port_map:
        raise RealUEDirectResolutionError(
            f"no matching native IPsec tuples found for ue_ip={ue_ip!r} and "
            f"pcscf_ip={pcscf_ip!r} in container {pcscf_container!r}"
        )

    observer_events = tuple(
        f"native-ipsec:port-map:{ue_port}->{pcscf_port}"
        for ue_port, pcscf_port in sorted(port_map.items())
    )
    return ResolvedNativeIPsecSession(
        ue_ip=ue_ip,
        pcscf_ip=pcscf_ip,
        port_map=port_map,
        observer_events=observer_events,
    )


@dataclass(frozen=True)
class IPsecSAStatus:
    """Result of checking whether IPsec Security Associations are alive."""

    alive: bool
    sa_count: int = 0
    detail: str = ""


def check_ipsec_sa_alive(
    *,
    pcscf_container: str = _DEFAULT_PCSCF_CONTAINER,
) -> IPsecSAStatus:
    """Check whether IPsec SAs exist in the P-CSCF container.

    Queries ``ip xfrm state`` inside the container and counts SAs whose
    source is a UE IP (10.20.20.x).  Returns ``alive=True`` only when at
    least one such SA is present.
    """
    try:
        result = subprocess.run(
            ["docker", "exec", pcscf_container, "ip", "xfrm", "state"],
            capture_output=True,
            text=True,
            timeout=10.0,
            check=False,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        return IPsecSAStatus(alive=False, detail=f"xfrm query failed: {exc}")

    if result.returncode != 0:
        error = result.stderr.strip() or result.stdout.strip() or "unknown error"
        return IPsecSAStatus(alive=False, detail=f"xfrm query error: {error}")

    # Count SAs whose src is a UE IP (10.20.20.x)
    sa_count = 0
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("src ") and " dst " in stripped:
            parts = stripped.split()
            if len(parts) >= 2 and parts[1].startswith("10.20.20."):
                sa_count += 1

    if sa_count > 0:
        return IPsecSAStatus(alive=True, sa_count=sa_count, detail=f"{sa_count} UE SAs found")
    return IPsecSAStatus(alive=False, sa_count=0, detail="no UE SAs found in xfrm state")


def check_route_to_target(target_ip: str) -> RouteCheckResult:
    system_name = platform.system()
    command = ["route", "-n", "get", target_ip]
    if system_name != "Darwin":
        command = ["ip", "route", "get", target_ip]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
    except FileNotFoundError as exc:
        return RouteCheckResult(False, f"route-check command not found: {exc.filename}")
    except subprocess.TimeoutExpired:
        return RouteCheckResult(False, "route-check command timed out")
    except OSError as exc:
        return RouteCheckResult(False, f"route-check failed: {exc}")

    details = (result.stdout or result.stderr).strip()
    if result.returncode != 0:
        return RouteCheckResult(
            False,
            details or f"route lookup exited with status {result.returncode}",
        )
    first_line = next(
        (line.strip() for line in details.splitlines() if line.strip()), ""
    )
    return RouteCheckResult(True, first_line or f"route available for {target_ip}")


def setup_route_to_target(
    target_ip: str,
    *,
    env: dict[str, str] | None = None,
) -> RouteCheckResult:
    source = os.environ if env is None else env
    ims_subnet = (
        _normalize_optional_text(source.get("VMF_REAL_UE_IMS_SUBNET"))
        or _DEFAULT_REAL_UE_IMS_SUBNET
    )
    upf_ip = (
        _normalize_optional_text(source.get("VMF_REAL_UE_UPF_IP"))
        or _DEFAULT_REAL_UE_UPF_IP
    )

    setup_result = setup_ue_route(ims_subnet=ims_subnet, upf_ip=upf_ip)
    if not setup_result.ok:
        return RouteCheckResult(False, setup_result.detail)

    route_result = check_route_to_target(target_ip)
    if route_result.ok:
        return route_result
    return RouteCheckResult(False, f"{setup_result.detail}; {route_result.detail}")


def normalize_direct_packet(
    packet: PacketModel,
    *,
    local_host: str,
    local_port: int,
) -> tuple[bytes, tuple[str, ...]]:
    updated_via = tuple(
        _rewrite_via_header(header, local_host=local_host, local_port=local_port)
        if index == 0
        else header
        for index, header in enumerate(packet.via)
    )
    payload = packet.model_copy(update={"via": updated_via}, deep=True)

    contact = getattr(payload, "contact", None)
    observer_events = ["direct-normalization:packet:via"]
    if contact:
        rewritten_contact = list(contact)
        rewritten = _rewrite_contact_name_address(
            rewritten_contact[0],
            local_host=local_host,
            local_port=local_port,
        )
        if rewritten is not None:
            rewritten_contact[0] = rewritten
            payload = payload.model_copy(
                update={"contact": tuple(rewritten_contact)},
                deep=True,
            )
            observer_events.append("direct-normalization:packet:contact")

    return render_packet_bytes(payload), tuple(observer_events)


def normalize_direct_wire_text(
    wire_text: str,
    *,
    local_host: str,
    local_port: int,
    rewrite_via: bool = True,
    rewrite_contact: bool = True,
) -> tuple[bytes, tuple[str, ...]]:
    if not wire_text:
        return b"", ("direct-normalization:wire-skipped:empty",)

    header_text, separator, body = wire_text.partition(f"{_CRLF}{_CRLF}")
    lines = header_text.split(_CRLF)
    if not lines:
        return wire_text.encode("utf-8"), ("direct-normalization:wire-skipped:empty",)

    updated_lines = [lines[0]]
    via_rewritten = False
    contact_rewritten = False
    for line in lines[1:]:
        if not via_rewritten and line.casefold().startswith("via:"):
            if rewrite_via:
                rewritten_line, changed = _rewrite_via_header_line(
                    line,
                    local_host=local_host,
                    local_port=local_port,
                )
                updated_lines.append(rewritten_line)
                via_rewritten = changed
            else:
                updated_lines.append(line)
            continue
        if not contact_rewritten and line.casefold().startswith("contact:"):
            if rewrite_contact:
                rewritten_line, changed = _rewrite_contact_header_line(
                    line,
                    local_host=local_host,
                    local_port=local_port,
                )
                updated_lines.append(rewritten_line)
                contact_rewritten = changed
            else:
                updated_lines.append(line)
            continue
        updated_lines.append(line)

    events: list[str] = []
    if not rewrite_via:
        events.append("direct-normalization:wire-skipped:via:preserve")
    elif via_rewritten:
        events.append("direct-normalization:wire:via")
    else:
        events.append("direct-normalization:wire-skipped:via")
    if not rewrite_contact:
        events.append("direct-normalization:wire-skipped:contact:preserve")
    elif contact_rewritten:
        events.append("direct-normalization:wire:contact")

    rendered = _CRLF.join(updated_lines)
    if separator:
        rendered = f"{rendered}{separator}{body}"
    return rendered.encode("utf-8"), tuple(events)


def prepare_real_ue_direct_payload(
    artifact: SendArtifact,
    *,
    local_host: str,
    local_port: int,
    rewrite_via: bool = True,
    rewrite_contact: bool = True,
) -> tuple[bytes, tuple[str, ...]]:
    if artifact.packet is not None:
        return normalize_direct_packet(
            artifact.packet,
            local_host=local_host,
            local_port=local_port,
        )
    if artifact.wire_text is not None:
        return normalize_direct_wire_text(
            artifact.wire_text,
            local_host=local_host,
            local_port=local_port,
            rewrite_via=rewrite_via,
            rewrite_contact=rewrite_contact,
        )
    assert artifact.packet_bytes is not None
    return artifact.packet_bytes, ("direct-normalization:bytes-unmodified",)


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _rewrite_via_header(
    header: ViaHeader,
    *,
    local_host: str,
    local_port: int,
) -> ViaHeader:
    return header.model_copy(
        update={
            "host": local_host,
            "port": local_port,
            "rport": True,
        },
        deep=True,
    )


def _rewrite_contact_name_address(
    value: NameAddress,
    *,
    local_host: str,
    local_port: int,
) -> NameAddress | None:
    if not isinstance(value.uri, SIPURI):
        return None
    return value.model_copy(
        update={
            "uri": value.uri.model_copy(
                update={"host": local_host, "port": local_port},
                deep=True,
            )
        },
        deep=True,
    )


def _rewrite_via_header_line(
    line: str,
    *,
    local_host: str,
    local_port: int,
) -> tuple[str, bool]:
    header_name, separator, value = line.partition(":")
    if not separator:
        return line, False
    stripped_value = value.strip()
    match = _VIA_SENT_BY_PATTERN.match(stripped_value)
    if match is None:
        return line, False
    suffix = match.group(3)
    if "rport" not in suffix.casefold():
        suffix = f"{suffix};rport"
    rewritten_value = f"{match.group(1)}{local_host}:{local_port}{suffix}"
    return f"{header_name}: {rewritten_value}", True


def _rewrite_contact_header_line(
    line: str,
    *,
    local_host: str,
    local_port: int,
) -> tuple[str, bool]:
    header_name, separator, value = line.partition(":")
    if not separator:
        return line, False
    match = _CONTACT_HOSTPORT_PATTERN.search(value)
    if match is None:
        return line, False
    rewritten_value = _CONTACT_HOSTPORT_PATTERN.sub(
        lambda match: f"{match.group(1)}{local_host}:{local_port}",
        value,
        count=1,
    )
    return f"{header_name}:{rewritten_value}", True


__all__ = [
    "RealUEDirectError",
    "RealUEDirectResolutionError",
    "RealUEDirectResolver",
    "RealUEDirectRouteError",
    "ResolvedNativeIPsecSession",
    "ResolvedRealUETarget",
    "RouteCheckResult",
    "UEContact",
    "check_route_to_target",
    "normalize_direct_wire_text",
    "prepare_real_ue_direct_payload",
    "resolve_native_ipsec_session",
    "resolve_ue_protected_ports",
    "setup_route_to_target",
]
