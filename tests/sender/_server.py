from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass, field


@dataclass
class UDPResponder:
    responses: tuple[bytes, ...]
    delay_seconds: float = 0.0
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
        self._thread.join(timeout=1.0)

    def _run(self) -> None:
        self._ready.set()
        try:
            data, addr = self.sock.recvfrom(65535)
        except OSError:
            return
        self.received_payloads.append(data)
        for response in self.responses:
            if self.delay_seconds:
                time.sleep(self.delay_seconds)
            try:
                self.sock.sendto(response, addr)
            except OSError:
                return


@dataclass
class TCPResponder:
    response: bytes
    received_payloads: list[bytes] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.host, self.port = self.sock.getsockname()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._ready = threading.Event()

    def start(self) -> None:
        self._thread.start()
        self._ready.wait(timeout=1.0)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass
        self._thread.join(timeout=1.0)

    def _run(self) -> None:
        self._ready.set()
        try:
            conn, _addr = self.sock.accept()
        except OSError:
            return
        with conn:
            data = conn.recv(65535)
            self.received_payloads.append(data)
            conn.sendall(self.response)
