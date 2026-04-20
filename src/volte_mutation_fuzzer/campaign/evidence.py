"""Collects evidence files for interesting (crash/suspicious/stack_failure) cases."""

import json
import logging
import shutil
from pathlib import Path

from volte_mutation_fuzzer.campaign.contracts import CaseResult

logger = logging.getLogger(__name__)

INTERESTING_VERDICTS: frozenset[str] = frozenset(
    {"crash", "stack_failure", "suspicious"}
)


class EvidenceCollector:
    """Saves per-case evidence directories for notable verdicts."""

    def __init__(self, base_dir: Path, *, enabled: bool = True) -> None:
        self._base_dir = base_dir / "interesting"
        self._enabled = enabled

    def should_collect(self, verdict: str) -> bool:
        return self._enabled and verdict in INTERESTING_VERDICTS

    def collect(
        self,
        case_result: CaseResult,
        *,
        sent_payload: str | bytes | None = None,
        pcap_path: str | None = None,
        adb_snapshot_dir: str | None = None,
        ios_snapshot_dir: str | None = None,
    ) -> str | None:
        """Collect evidence for one case. Returns the evidence directory path, or None."""
        if not self.should_collect(case_result.verdict):
            return None

        case_dir = self._base_dir / f"case_{case_result.case_id:06d}"
        try:
            case_dir.mkdir(parents=True, exist_ok=True)

            # 1. summary.json — seed, strategy, reproduction info
            summary = {
                "case_id": case_result.case_id,
                "seed": case_result.seed,
                "method": case_result.method,
                "profile": case_result.profile,
                "layer": case_result.layer,
                "strategy": case_result.strategy,
                "verdict": case_result.verdict,
                "reason": case_result.reason,
                "response_code": case_result.response_code,
                "elapsed_ms": case_result.elapsed_ms,
                "mutation_ops": list(case_result.mutation_ops),
                "reproduction_cmd": case_result.reproduction_cmd,
                "timestamp": case_result.timestamp,
                "error": case_result.error,
                "details": case_result.details,
            }
            (case_dir / "summary.json").write_text(
                json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )

            # 2. sent.sip — the actual payload that was sent
            if sent_payload is not None:
                if isinstance(sent_payload, bytes):
                    (case_dir / "sent.bin").write_bytes(sent_payload)
                else:
                    (case_dir / "sent.sip").write_text(
                        sent_payload, encoding="utf-8"
                    )

            # 3. response.sip — raw response from target
            if case_result.raw_response:
                (case_dir / "response.sip").write_text(
                    case_result.raw_response, encoding="utf-8"
                )

            # 4. capture.pcap — copy from pcap dir
            if pcap_path and Path(pcap_path).is_file():
                shutil.copy2(pcap_path, case_dir / "capture.pcap")

            # 5. adb_log.txt — copy from adb snapshot dir
            if adb_snapshot_dir and Path(adb_snapshot_dir).is_dir():
                adb_dest = case_dir / "adb_log.txt"
                # ADB snapshot may contain multiple files; concatenate them
                parts: list[str] = []
                for f in sorted(Path(adb_snapshot_dir).iterdir()):
                    if f.is_file():
                        parts.append(f"=== {f.name} ===\n")
                        parts.append(f.read_text(encoding="utf-8", errors="replace"))
                        parts.append("\n")
                if parts:
                    adb_dest.write_text("".join(parts), encoding="utf-8")

            # 6. ios_log.txt — flatten the iOS snapshot tree for quick review
            if ios_snapshot_dir and Path(ios_snapshot_dir).is_dir():
                ios_dest = case_dir / "ios_log.txt"
                parts = []
                for f in sorted(Path(ios_snapshot_dir).rglob("*")):
                    if not f.is_file():
                        continue
                    rel = f.relative_to(ios_snapshot_dir)
                    parts.append(f"=== {rel} ===\n")
                    parts.append(f.read_text(encoding="utf-8", errors="replace"))
                    parts.append("\n")
                if parts:
                    ios_dest.write_text("".join(parts), encoding="utf-8")

            # 7. mutation_ops.txt
            if case_result.mutation_ops:
                (case_dir / "mutation_ops.txt").write_text(
                    "\n".join(case_result.mutation_ops) + "\n",
                    encoding="utf-8",
                )

            logger.info(
                "evidence collected for case %d (%s): %s",
                case_result.case_id,
                case_result.verdict,
                case_dir,
            )
            return str(case_dir)

        except Exception as exc:
            logger.warning(
                "failed to collect evidence for case %d: %s",
                case_result.case_id,
                exc,
            )
            return None
