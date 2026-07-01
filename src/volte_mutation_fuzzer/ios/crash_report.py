"""Identify *new* iOS crash reports captured during a campaign.

``idevicecrashreport`` copies the entire on-device crash store every time it
runs (``-k`` keeps the reports on the device), and it cannot pull incrementally.
The fix the campaign uses: snapshot the crash-file name set once at start
(baseline), pull once again at the end, and treat the set difference as the
crashes that actually appeared during the run. This module turns those pulled
``.ips`` files into annotated records (authoritative timestamp + bug type) so the
finalize step can write a short, honest summary instead of hundreds of months-old
reports duplicated under every case folder.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

# .ips filename timestamp formats observed on iOS 26:
#   stacks-2026-05-28-223412.ips                 -> YYYY-MM-DD-HHMMSS
#   JetsamEvent-2026-05-30-023243.ips            -> YYYY-MM-DD-HHMMSS
#   SiriSearchFeedback-2026-06-07-024606.000.ips -> YYYY-MM-DD-HHMMSS(.fraction)
#   OTAUpdate-2026-06-01-00-50-57.ips            -> YYYY-MM-DD-HH-MM-SS
_TS_COMPACT = re.compile(r"(\d{4})-(\d{2})-(\d{2})-(\d{2})(\d{2})(\d{2})(?:\D|$)")
_TS_DASHED = re.compile(r"(\d{4})-(\d{2})-(\d{2})-(\d{2})-(\d{2})-(\d{2})(?:\D|$)")


def parse_crash_timestamp(filename: str) -> datetime | None:
    """Parse the crash time embedded in an ``.ips`` filename (normalized to UTC).

    Filenames carry device wall-clock time without a zone; we tag it UTC so it is
    comparable with the (UTC) campaign footer. Prefer :func:`parse_content_timestamp`
    when the report's JSON header is available — that one is zone-aware.
    """
    # Match the dashed-time form first: its prefix is a superset of the compact
    # form's date prefix, so trying compact first would mis-read the hour.
    match = _TS_DASHED.search(filename) or _TS_COMPACT.search(filename)
    if match is None:
        return None
    year, month, day, hour, minute, second = (int(g) for g in match.groups())
    try:
        return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except ValueError:
        return None


def parse_content_timestamp(path: Path) -> tuple[datetime | None, str | None]:
    """Read ``timestamp`` and ``bug_type`` from an ``.ips`` JSON header.

    Modern iOS ``.ips`` files start with a one-line JSON header such as::

        {"bug_type":"309","timestamp":"2026-06-07 02:46:06.00 +0000", ...}

    Returns ``(timestamp_utc, bug_type)`` with either element ``None`` when absent
    or unparseable (e.g. legacy plaintext ``.crash`` dumps).
    """
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            first = handle.readline().strip()
    except OSError:
        return None, None
    if not first.startswith("{"):
        return None, None
    try:
        header = json.loads(first)
    except json.JSONDecodeError:
        return None, None
    bug_type = header.get("bug_type")
    raw_ts = header.get("timestamp")
    timestamp: datetime | None = None
    if isinstance(raw_ts, str):
        cleaned = re.sub(r"\.\d+", "", raw_ts).strip()  # drop sub-second fraction
        for fmt in ("%Y-%m-%d %H:%M:%S %z", "%Y-%m-%d %H:%M:%S"):
            try:
                parsed = datetime.strptime(cleaned, fmt)
            except ValueError:
                continue
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            timestamp = parsed.astimezone(timezone.utc)
            break
    return timestamp, (str(bug_type) if bug_type is not None else None)


@dataclass(frozen=True)
class CrashRecord:
    name: str
    timestamp: datetime | None
    timestamp_source: str  # "content" | "filename" | "none"
    bug_type: str | None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "name": self.name,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "timestamp_source": self.timestamp_source,
            "bug_type": self.bug_type,
        }


def iter_crash_files(base: str | Path) -> list[Path]:
    """List ``.ips`` (and retired ``*.ips.ca`` etc.) files under ``base``."""
    root = Path(base)
    if not root.exists():
        return []
    return [p for p in root.rglob("*") if p.is_file() and ".ips" in p.name]


def _describe(path: Path) -> CrashRecord:
    content_ts, bug_type = parse_content_timestamp(path)
    if content_ts is not None:
        return CrashRecord(path.name, content_ts, "content", bug_type)
    filename_ts = parse_crash_timestamp(path.name)
    if filename_ts is not None:
        return CrashRecord(path.name, filename_ts, "filename", bug_type)
    return CrashRecord(path.name, None, "none", bug_type)


def describe_new_crashes(
    crash_dir: str | Path,
    *,
    baseline_names: frozenset[str] | set[str] = frozenset(),
) -> list[CrashRecord]:
    """Annotate every ``.ips`` under ``crash_dir`` not present in ``baseline_names``.

    De-duplicated by filename, sorted oldest-first (records with no parseable
    timestamp sort last).
    """
    seen: dict[str, CrashRecord] = {}
    for path in iter_crash_files(crash_dir):
        if path.name in baseline_names or path.name in seen:
            continue
        seen[path.name] = _describe(path)
    records = list(seen.values())
    far_future = datetime.max.replace(tzinfo=timezone.utc)
    records.sort(key=lambda r: (r.timestamp or far_future, r.name))
    return records
