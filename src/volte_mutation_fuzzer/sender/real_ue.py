from __future__ import annotations

import json
import os
import platform
import re
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Final

from volte_mutation_fuzzer.sender.contracts import SendArtifact, TargetEndpoint
from volte_mutation_fuzzer.sip.common import NameAddress, SIPURI, ViaHeader
from volte_mutation_fuzzer.sip.render import PacketModel, render_packet_bytes

_CRLF: Final[str] = "\r\n"
_DEFAULT_SCSCF_CONTAINER: Final[str] = "scscf"
_DEFAULT_PCSCF_CONTAINER: Final[str] = "pcscf"
_DEFAULT_PCSCF_LOG_TAIL: Final[int] = 500
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
class UEContact:
    msisdn: str
    host: str
    port: int
    source: str


@dataclass(frozen=True)
class ResolvedRealUETarget:
    host: str
    port: int
    label: str | None
    observer_events: tuple[str, ...]


@dataclass(frozen=True)
class RouteCheckResult:
    ok: bool
    detail: str


class RealUEDirectResolver:
    """Resolves capstone-style real UE targets from static or lab-backed sources."""

    def __init__(self, env: dict[str, str] | None = None) -> None:
        source = os.environ if env is None else env
        self.scscf_container = source.get(
            "VMF_REAL_UE_SCSCF_CONTAINER", _DEFAULT_SCSCF_CONTAINER
        )
        self.pcscf_container = source.get(
            "VMF_REAL_UE_PCSCF_CONTAINER", _DEFAULT_PCSCF_CONTAINER
        )
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

    def resolve(self, target: TargetEndpoint) -> ResolvedRealUETarget:
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
            contact = self._lookup_via_pcscf_logs(msisdn)
        if contact is None:
            raise RealUEDirectResolutionError(
                f"real-ue-direct target msisdn {msisdn} could not be resolved via "
                "docker Kamailio or P-CSCF log backends"
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

    def _parse_kamctl_output(self, msisdn: str, output: str) -> UEContact | None:
        direct_match = _KAMCTL_CONTACT_PATTERN.search(output)
        if direct_match is not None:
            return UEContact(
                msisdn=msisdn,
                host=direct_match.group(1),
                port=int(direct_match.group(2)),
                source="kamctl",
            )

        current_aor_matches = False
        for line in output.splitlines():
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
            rewritten_line, changed = _rewrite_via_header_line(
                line,
                local_host=local_host,
                local_port=local_port,
            )
            updated_lines.append(rewritten_line)
            via_rewritten = changed
            continue
        if not contact_rewritten and line.casefold().startswith("contact:"):
            rewritten_line, changed = _rewrite_contact_header_line(
                line,
                local_host=local_host,
                local_port=local_port,
            )
            updated_lines.append(rewritten_line)
            contact_rewritten = changed
            continue
        updated_lines.append(line)

    events: list[str] = []
    if via_rewritten:
        events.append("direct-normalization:wire:via")
    else:
        events.append("direct-normalization:wire-skipped:via")
    if contact_rewritten:
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
    "ResolvedRealUETarget",
    "RouteCheckResult",
    "UEContact",
    "check_route_to_target",
    "prepare_real_ue_direct_payload",
]
