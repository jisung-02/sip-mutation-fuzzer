"""Multi-request/response UDP test server for dialog fuzzing tests."""

import socket
import threading
from dataclasses import dataclass, field


@dataclass
class DialogUDPResponder:
    """UDP server that handles multiple SIP requests sequentially.

    For each incoming request, it parses the SIP method from the first line
    and returns the matching pre-configured response. If no response is
    configured for a method, no response is sent (simulates silence).

    ``responses_by_method`` maps uppercase SIP method names to the raw bytes
    response to send back. Use an empty bytes value to simulate no response
    (e.g., ACK which does not generate a response).
    """

    responses_by_method: dict[str, bytes]
    max_requests: int = 10
    received_payloads: list[bytes] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.host, self.port = self.sock.getsockname()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._ready = threading.Event()
        self._stop = threading.Event()

    def start(self) -> None:
        self._thread.start()
        self._ready.wait(timeout=1.0)

    def close(self) -> None:
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2.0)

    def _run(self) -> None:
        self._ready.set()
        self.sock.settimeout(0.5)
        count = 0
        while count < self.max_requests and not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except TimeoutError:
                continue
            except OSError:
                break

            self.received_payloads.append(data)
            count += 1
            method = _extract_method(data)
            response = self.responses_by_method.get(method, b"")
            if response:
                try:
                    self.sock.sendto(response, addr)
                except OSError:
                    break


def _extract_method(data: bytes) -> str:
    """Extract the SIP method from the first line of a SIP request."""
    try:
        first_line = data.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
        return first_line.split(" ", 1)[0].strip().upper()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Helpers to build SIP response bytes for tests
# ---------------------------------------------------------------------------

_CRLF = "\r\n"
IMS_DOMAIN = "ims.mnc001.mcc001.3gppnetwork.org"
REALISTIC_CALL_ID = "a84b4c76e66710@pcscf.ims.mnc001.mcc001.3gppnetwork.org"
REMOTE_URI = f"sip:remote@{IMS_DOMAIN}"
UE_URI = f"sip:111111@{IMS_DOMAIN}"


def make_200_ok(
    call_id: str = REALISTIC_CALL_ID,
    to_tag: str = "uas-tag-abc",
    contact: str = "sip:111111@127.0.0.1:5060",
    cseq: str = "1 INVITE",
) -> bytes:
    """Build a minimal 200 OK response bytes for INVITE."""
    msg = (
        f"SIP/2.0 200 OK{_CRLF}"
        f"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKtest{_CRLF}"
        f"From: <{REMOTE_URI}>;tag=uac-tag{_CRLF}"
        f"To: <{UE_URI}>;tag={to_tag}{_CRLF}"
        f"Call-ID: {call_id}{_CRLF}"
        f"CSeq: {cseq}{_CRLF}"
        f"Contact: <{contact}>{_CRLF}"
        f"Content-Length: 0{_CRLF}"
        f"{_CRLF}"
    )
    return msg.encode("utf-8")


def make_180_ringing(
    call_id: str = REALISTIC_CALL_ID,
    cseq: str = "1 INVITE",
) -> bytes:
    """Build a minimal 180 Ringing response bytes."""
    msg = (
        f"SIP/2.0 180 Ringing{_CRLF}"
        f"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKtest{_CRLF}"
        f"From: <{REMOTE_URI}>;tag=uac-tag{_CRLF}"
        f"To: <{UE_URI}>{_CRLF}"
        f"Call-ID: {call_id}{_CRLF}"
        f"CSeq: {cseq}{_CRLF}"
        f"Content-Length: 0{_CRLF}"
        f"{_CRLF}"
    )
    return msg.encode("utf-8")


def make_486_busy() -> bytes:
    """Build a 486 Busy Here response bytes."""
    msg = (
        f"SIP/2.0 486 Busy Here{_CRLF}"
        f"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKtest{_CRLF}"
        f"From: <{REMOTE_URI}>;tag=uac-tag{_CRLF}"
        f"To: <{UE_URI}>;tag=busy-tag{_CRLF}"
        f"Call-ID: {REALISTIC_CALL_ID}{_CRLF}"
        f"CSeq: 1 INVITE{_CRLF}"
        f"Content-Length: 0{_CRLF}"
        f"{_CRLF}"
    )
    return msg.encode("utf-8")


def make_200_ok_generic(method: str = "BYE") -> bytes:
    """Build a generic 200 OK for non-INVITE methods."""
    msg = (
        f"SIP/2.0 200 OK{_CRLF}"
        f"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKtest{_CRLF}"
        f"From: <{REMOTE_URI}>;tag=uac-tag{_CRLF}"
        f"To: <{UE_URI}>;tag=uas-tag-abc{_CRLF}"
        f"Call-ID: {REALISTIC_CALL_ID}{_CRLF}"
        f"CSeq: 2 {method}{_CRLF}"
        f"Content-Length: 0{_CRLF}"
        f"{_CRLF}"
    )
    return msg.encode("utf-8")
