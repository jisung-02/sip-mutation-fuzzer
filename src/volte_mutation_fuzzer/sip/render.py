from __future__ import annotations

from typing import Any, TypeAlias

from volte_mutation_fuzzer.mutator.editable import (
    EditableHeader,
    EditablePacketBytes,
    EditableSIPMessage,
    EditableStartLine,
)
from volte_mutation_fuzzer.sip.catalog import SIP_CATALOG, SIPCatalog
from volte_mutation_fuzzer.sip.common import (
    AbsoluteURI,
    AuthChallenge,
    CSeqHeader,
    EventHeader,
    NameAddress,
    RAckHeader,
    RetryAfterHeader,
    SIPFieldLocation,
    SIPURI,
    SubscriptionStateHeader,
    ViaHeader,
)
from volte_mutation_fuzzer.sip.requests import SIPRequest, SIPRequestDefinition
from volte_mutation_fuzzer.sip.responses import SIPResponse, SIPResponseDefinition

PacketModel: TypeAlias = SIPRequest | SIPResponse
PacketDefinition: TypeAlias = SIPRequestDefinition | SIPResponseDefinition


def packet_to_editable_message(
    packet: PacketModel,
    *,
    catalog: SIPCatalog | None = None,
) -> EditableSIPMessage:
    resolved_catalog = SIP_CATALOG if catalog is None else catalog
    definition = _resolve_packet_definition(packet, resolved_catalog)
    headers: list[EditableHeader] = []

    for descriptor in definition.field_descriptors:
        if descriptor.location != SIPFieldLocation.HEADER:
            continue

        value = getattr(packet, descriptor.python_name)
        if value is None:
            continue

        values = tuple(value) if descriptor.repeatable else (value,)
        for item in values:
            headers.append(
                EditableHeader(
                    name=descriptor.wire_name,
                    value=_serialize_wire_value(descriptor.python_name, item),
                )
            )

    return EditableSIPMessage(
        start_line=EditableStartLine(text=_serialize_start_line(packet)),
        headers=tuple(headers),
        body=packet.body or "",
        declared_content_length=int(packet.content_length),
    )


def render_packet(packet: PacketModel, *, catalog: SIPCatalog | None = None) -> str:
    return packet_to_editable_message(packet, catalog=catalog).render()


def render_packet_bytes(
    packet: PacketModel,
    *,
    catalog: SIPCatalog | None = None,
) -> bytes:
    return EditablePacketBytes.from_message(
        packet_to_editable_message(packet, catalog=catalog)
    ).data


def _resolve_packet_definition(
    packet: PacketModel,
    catalog: SIPCatalog,
) -> PacketDefinition:
    if isinstance(packet, SIPRequest):
        return catalog.get_request(packet.method)
    return catalog.get_response(packet.status_code)


def _serialize_start_line(packet: PacketModel) -> str:
    if isinstance(packet, SIPRequest):
        return (
            f"{packet.method} "
            f"{_serialize_uri_reference(packet.request_uri)} "
            f"{packet.sip_version}"
        )
    return f"{packet.sip_version} {packet.status_code} {packet.reason_phrase}"


def _serialize_wire_value(python_name: str, value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    if isinstance(value, SIPURI | AbsoluteURI):
        return _serialize_uri_reference(value)
    if isinstance(value, NameAddress):
        return _serialize_name_address(value)
    if isinstance(value, ViaHeader):
        return _serialize_via_header(value)
    if isinstance(value, CSeqHeader):
        return f"{value.sequence} {value.method}"
    if isinstance(value, EventHeader):
        return _serialize_parameterized_value(value.package, value.parameters)
    if isinstance(value, SubscriptionStateHeader):
        parameters = dict(value.parameters)
        if value.expires is not None:
            parameters["expires"] = str(value.expires)
        if value.reason is not None:
            parameters["reason"] = value.reason
        if value.retry_after is not None:
            parameters["retry-after"] = str(value.retry_after)
        return _serialize_parameterized_value(value.state, parameters)
    if isinstance(value, RAckHeader):
        return f"{value.response_num} {value.cseq_num} {value.method}"
    if isinstance(value, RetryAfterHeader):
        rendered = str(value.seconds)
        if value.comment is not None:
            rendered = f"{rendered} ({value.comment})"
        parameters = dict(value.parameters)
        if value.duration is not None:
            parameters["duration"] = str(value.duration)
        return rendered + _serialize_parameters(parameters)
    if isinstance(value, AuthChallenge):
        parameters: list[str] = [
            f'realm="{value.realm}"',
            f'nonce="{value.nonce}"',
        ]
        if value.algorithm is not None:
            parameters.append(f"algorithm={value.algorithm}")
        if value.opaque is not None:
            parameters.append(f'opaque="{value.opaque}"')
        if value.qop is not None:
            parameters.append(f'qop="{",".join(value.qop)}"')
        if value.stale is not None:
            parameters.append(f"stale={'true' if value.stale else 'false'}")
        for key, item in value.parameters.items():
            parameters.append(f"{key}={item}")
        return f"{value.scheme} " + ", ".join(parameters)
    if isinstance(value, dict):
        return _serialize_dict_value(python_name, value)
    return str(value)


def _serialize_uri_reference(value: SIPURI | AbsoluteURI) -> str:
    if isinstance(value, AbsoluteURI):
        return value.uri

    if value.scheme == "tel":
        rendered = f"tel:{value.user}"
    else:
        authority = ""
        if value.user is not None:
            authority = value.user
            if value.password is not None:
                authority = f"{authority}:{value.password}"
            authority = f"{authority}@"
        rendered = f"{value.scheme}:{authority}{value.host}"
        if value.port is not None:
            rendered = f"{rendered}:{value.port}"

    rendered += _serialize_parameters(value.parameters)
    if value.headers:
        rendered += "?" + "&".join(
            f"{key}={item}" for key, item in value.headers.items()
        )
    return rendered


def _serialize_name_address(value: NameAddress) -> str:
    rendered = f"<{_serialize_uri_reference(value.uri)}>"
    if value.display_name is not None:
        rendered = f'"{value.display_name}" {rendered}'
    return rendered + _serialize_parameters(value.parameters)


def _serialize_via_header(value: ViaHeader) -> str:
    rendered = f"SIP/2.0/{value.transport} {value.host}"
    if value.port is not None:
        rendered = f"{rendered}:{value.port}"

    parameters: dict[str, str | None] = {"branch": value.branch}
    if value.received is not None:
        parameters["received"] = value.received
    if value.rport is True:
        parameters["rport"] = None
    elif value.rport is not None:
        parameters["rport"] = str(value.rport)
    if value.maddr is not None:
        parameters["maddr"] = value.maddr
    if value.ttl is not None:
        parameters["ttl"] = str(value.ttl)
    parameters.update(value.parameters)
    return rendered + _serialize_parameters(parameters)


def _serialize_parameterized_value(
    base: str,
    parameters: dict[str, str | None],
) -> str:
    return base + _serialize_parameters(parameters)


def _serialize_parameters(parameters: dict[str, str | None]) -> str:
    if not parameters:
        return ""
    return "".join(
        f";{key}" if item is None else f";{key}={item}"
        for key, item in parameters.items()
    )


def _serialize_dict_value(python_name: str, value: dict[str, Any]) -> str:
    if python_name == "authentication_info":
        return ", ".join(f"{key}={item}" for key, item in value.items())
    return ", ".join(
        f"{key}={item}" if item is not None else key for key, item in value.items()
    )


__all__ = [
    "PacketModel",
    "packet_to_editable_message",
    "render_packet",
    "render_packet_bytes",
]
