"""Check Android telephony call state via ADB.

Used between INVITE fuzzing cases to confirm the device has returned to
IDLE before sending the next INVITE.  Avoids polluting subsequent test
cases with residual ringing/offhook state from a previous INVITE.
"""

import logging
import time
from enum import IntEnum

from volte_mutation_fuzzer.adb.core import AdbConnector

logger = logging.getLogger(__name__)


class CallState(IntEnum):
    """Android TelephonyManager call states (CALL_STATE_*)."""

    IDLE = 0
    RINGING = 1
    OFFHOOK = 2
    UNKNOWN = -1


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

_DEFAULT_POLL_INTERVAL: float = 0.5  # seconds between polls
_DEFAULT_WAIT_TIMEOUT: float = 10.0  # max seconds to wait for IDLE


class CallStateChecker:
    """Query and wait for Android telephony call state via ``dumpsys``."""

    def __init__(
        self,
        serial: str | None = None,
        *,
        poll_interval: float = _DEFAULT_POLL_INTERVAL,
        wait_timeout: float = _DEFAULT_WAIT_TIMEOUT,
    ) -> None:
        self._connector = AdbConnector(serial=serial)
        self._poll_interval = poll_interval
        self._wait_timeout = wait_timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_call_state(self) -> CallState:
        """Return the current mCallState from telephony.registry."""
        try:
            result = self._connector.run_shell(
                "dumpsys", "telephony.registry",
                timeout=5,
            )
        except Exception as exc:
            logger.warning("call state query failed: %s", exc)
            return CallState.UNKNOWN

        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("mCallState="):
                try:
                    value = int(stripped.split("=", 1)[1])
                    return CallState(value)
                except (ValueError, IndexError):
                    pass

        return CallState.UNKNOWN

    def is_idle(self) -> bool:
        """Return True if the device reports IDLE call state."""
        return self.get_call_state() == CallState.IDLE

    def wait_for_idle(self) -> list[str]:
        """Poll until the device is IDLE or timeout expires.

        Returns a list of observer-event strings describing what happened.
        """
        events: list[str] = []
        state = self.get_call_state()

        if state == CallState.IDLE:
            return events

        if state == CallState.UNKNOWN:
            events.append("call-state:unknown:skip-wait")
            return events

        events.append(f"call-state:waiting:state={state.name}")
        deadline = time.monotonic() + self._wait_timeout
        polls = 0

        while time.monotonic() < deadline:
            time.sleep(self._poll_interval)
            polls += 1
            state = self.get_call_state()
            if state == CallState.IDLE:
                events.append(
                    f"call-state:idle-ok:polls={polls}"
                    f":waited={self._wait_timeout - (deadline - time.monotonic()):.1f}s"
                )
                return events

        # Timed out — device still not IDLE.
        events.append(
            f"call-state:timeout:state={state.name}"
            f":polls={polls}:limit={self._wait_timeout}s"
        )
        return events
