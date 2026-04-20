import logging
import json
import os
import re
import sys
import time
import uuid
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, cast

from volte_mutation_fuzzer.campaign.contracts import (
    CampaignConfig,
    CampaignResult,
    CampaignSummary,
    CaseResult,
    CaseSpec,
)
from volte_mutation_fuzzer.capture.core import PcapCapture
from volte_mutation_fuzzer.dialog.core import DialogOrchestrator
from volte_mutation_fuzzer.dialog.scenarios import scenario_for_method
from volte_mutation_fuzzer.generator.contracts import (
    DialogContext,
    GeneratorSettings,
    RequestSpec,
    ResponseSpec,
)
from volte_mutation_fuzzer.generator.core import SIPGenerator
from volte_mutation_fuzzer.generator.real_ue_mt_template import (
    build_default_slots,
    load_mt_invite_template,
    render_mt_invite,
)
from volte_mutation_fuzzer.mutator.contracts import (
    MutationConfig,
    MutatedCase,
    PacketModel,
)
from volte_mutation_fuzzer.mutator.profile_catalog import profile_supports_strategy
from volte_mutation_fuzzer.mutator.core import SIPMutator
from volte_mutation_fuzzer.mutator.editable import parse_editable_from_wire
from volte_mutation_fuzzer.oracle.contracts import OracleContext
from volte_mutation_fuzzer.oracle.core import (
    AdbOracle,
    IosOracle,
    LogOracle,
    OracleEngine,
)
from volte_mutation_fuzzer.sender.contracts import (
    SendArtifact,
    SendReceiveResult,
    TargetEndpoint,
    TargetMode,
    TransportProtocol,
)
from volte_mutation_fuzzer.sender.core import SIPSenderReactor
from volte_mutation_fuzzer.sender.real_ue import RealUEDirectResolver, check_ipsec_sa_alive
from volte_mutation_fuzzer.sip.catalog import SIP_CATALOG
from volte_mutation_fuzzer.sip.common import SIPMethod, SIPURI
from volte_mutation_fuzzer.sip.completeness import (
    PacketCompletionTier,
    PacketRuntimePath,
    get_packet_completion,
)
from volte_mutation_fuzzer.sip.render import render_packet
from volte_mutation_fuzzer.analysis.crash_analyzer import CampaignCrashAnalyzer
from volte_mutation_fuzzer.campaign.dashboard import ConsoleProgressReporter
from volte_mutation_fuzzer.campaign.evidence import EvidenceCollector
from volte_mutation_fuzzer.campaign.report import HtmlReportGenerator

_DEFAULT_PCSCF_IP: str = "172.22.0.21"
_MT_TEMPLATE_FRAG_LIMIT: int = 65535  # bytes; raised — Docker bridge IP reassembly works fine in practice

# INVITE teardown constants
_CANCEL_MAX_RETRIES: int = 3
_CANCEL_RETRY_INTERVAL: float = 0.5  # seconds between retries
_CANCEL_TEARDOWN_TIMEOUT: float = 2.0  # extra cooldown when teardown fails

logger = logging.getLogger(__name__)

_DIALOG_RUNTIME_PATHS: frozenset[PacketRuntimePath] = frozenset(
    {
        PacketRuntimePath.invite_dialog,
        PacketRuntimePath.invite_ack,
        PacketRuntimePath.invite_cancel,
        PacketRuntimePath.invite_prack,
    }
)


# layer별 지원 전략 매핑 — mutator/core.py _validate_supported_strategy와 동기화
_SUPPORTED_STRATEGIES: dict[str, frozenset[str]] = {
    "model": frozenset({"default", "state_breaker"}),
    "wire": frozenset(
        {
            "default",
            "identity",
            "safe",
            "header_whitespace_noise",
            "final_crlf_loss",
            "duplicate_content_length_conflict",
            "alias_port_desync",
        }
    ),
    "byte": frozenset(
        {
            "default",
            "identity",
            "safe",
            "header_targeted",
            "tail_chop_1",
            "tail_garbage",
        }
    ),
}


# ---------------------------------------------------------------------------
# CaseGenerator
# ---------------------------------------------------------------------------


class CaseGenerator:
    """Produces CaseSpec instances from direct method and response selections."""

    def __init__(self, config: CampaignConfig) -> None:
        self._config = config

    def generate(self, skip_before: int = -1) -> Iterator[CaseSpec]:
        config = self._config
        seen: set[tuple[str, str, int | None, str | None, str, str]] = set()
        combos: list[tuple[str, str, int | None, str | None, str, str]] = []

        # Template mode: drop model layer (3GPP wire text used directly)
        template_active = config.mt_invite_template is not None

        effective_layers = (
            tuple(lyr for lyr in config.layers if lyr != "model")
            if template_active
            else config.layers
        )

        for method in config.methods:
            for profile in config.profiles:
                for layer in effective_layers:
                    for strategy in config.strategies:
                        if strategy not in _SUPPORTED_STRATEGIES.get(
                            layer, frozenset()
                        ):
                            continue
                        if not profile_supports_strategy(profile, layer, strategy):
                            continue
                        key = (profile, method, None, None, layer, strategy)
                        if key not in seen:
                            seen.add(key)
                            combos.append(key)

        for response_code in config.response_codes:
            response_definition = SIP_CATALOG.get_response(response_code)
            related_methods = tuple(
                method.value for method in response_definition.related_methods
            ) or ("INVITE",)
            for related_method in related_methods:
                for profile in config.profiles:
                    for layer in config.layers:
                        for strategy in config.strategies:
                            if strategy not in _SUPPORTED_STRATEGIES.get(
                                layer, frozenset()
                            ):
                                continue
                            if not profile_supports_strategy(profile, layer, strategy):
                                continue
                            key = (
                                profile,
                                related_method,
                                response_code,
                                related_method,
                                layer,
                                strategy,
                            )
                            if key not in seen:
                                seen.add(key)
                                combos.append(key)

        # Build the recurring combo list (excludes identity baseline).
        # Round 0 uses full combos (including identity if template_active),
        # subsequent rounds use only recurring_combos.
        recurring_combos = [
            c
            for c in combos
            if not (
                c[1] == "INVITE"
                and c[2] is None
                and c[3] is None
                and c[4] == "wire"
                and c[5] == "identity"
            )
        ]

        unlimited = config.max_cases == 0
        case_id = 0
        round_num = 0
        while True:
            round_combos = combos if round_num == 0 else recurring_combos
            for (
                profile,
                method,
                response_code,
                related_method,
                layer,
                strategy,
            ) in round_combos:
                if not unlimited and case_id >= config.max_cases:
                    return
                if case_id <= skip_before:
                    case_id += 1
                    continue
                yield CaseSpec(
                    case_id=case_id,
                    seed=config.seed_start + case_id,
                    profile=profile,
                    method=method,
                    layer=layer,
                    strategy=strategy,
                    response_code=response_code,
                    related_method=related_method,
                )
                case_id += 1
            round_num += 1
            # Guard: if no recurring combos, stop after round 0
            if not recurring_combos:
                return


# ---------------------------------------------------------------------------
# ResultStore
# ---------------------------------------------------------------------------


class ResultStore:
    """Appends CaseResult records to a JSON Lines file."""

    _HEADER_TYPE = "header"
    _CASE_TYPE = "case"
    _FOOTER_TYPE = "footer"

    def __init__(self, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def write_header(self, result: CampaignResult) -> None:
        payload = {"type": self._HEADER_TYPE}
        payload.update(result.model_dump(mode="json"))
        with self._path.open("w", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")

    def append(self, result: CaseResult) -> None:
        payload = {"type": self._CASE_TYPE}
        payload.update(result.model_dump(mode="json"))
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")

    def write_footer(self, result: CampaignResult) -> None:
        payload = {"type": self._FOOTER_TYPE}
        payload.update(result.model_dump(mode="json"))
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")

    def find_checkpoint(self) -> tuple[int, CampaignSummary, str, str, "CampaignConfig"] | None:
        """Return (last_case_id, summary, campaign_id, started_at, original_config) or None."""
        if not self._path.exists():
            return None
        try:
            header, cases = self.read_all()
        except Exception:
            return None
        if not cases:
            return None
        last_id = max(c.case_id for c in cases)
        counts: dict[str, int] = {
            "normal": 0,
            "suspicious": 0,
            "timeout": 0,
            "crash": 0,
            "stack_failure": 0,
            "infra_failure": 0,
            "unknown": 0,
        }
        for c in cases:
            if c.verdict in counts:
                counts[c.verdict] += 1
        summary = CampaignSummary(total=len(cases), **counts)
        return last_id, summary, header.campaign_id, header.started_at, header.config

    def write_resume_marker(self, resume_from_case_id: int) -> None:
        """Append a resume_marker line without overwriting existing records."""
        payload = {
            "type": "resume_marker",
            "resumed_at": datetime.now(timezone.utc).isoformat(),
            "resume_from_case_id": resume_from_case_id,
        }
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")

    def read_all(self) -> tuple[CampaignResult, list[CaseResult]]:
        lines = self._path.read_text(encoding="utf-8").splitlines()
        header: CampaignResult | None = None
        cases: list[CaseResult] = []
        for line in lines:
            if not line.strip():
                continue
            obj = json.loads(line)
            t = obj.pop("type", None)
            if t == self._HEADER_TYPE:
                header = CampaignResult.model_validate(obj)
            elif t == self._FOOTER_TYPE:
                header = CampaignResult.model_validate(obj)
            elif t == self._CASE_TYPE:
                cases.append(CaseResult.model_validate(obj))
        if header is None:
            raise ValueError(f"no header found in {self._path}")
        return header, cases

    def read_case(self, case_id: int) -> CaseResult | None:
        _, cases = self.read_all()
        for case in cases:
            if case.case_id == case_id:
                return case
        return None


# ---------------------------------------------------------------------------
# CampaignExecutor
# ---------------------------------------------------------------------------


class CampaignExecutor:
    """Sequential campaign loop: generate → mutate → send → judge → store."""

    def __init__(
        self,
        config: CampaignConfig,
        generator: SIPGenerator | None = None,
        mutator: SIPMutator | None = None,
        sender: SIPSenderReactor | None = None,
        oracle: OracleEngine | None = None,
        store: ResultStore | None = None,
        campaign_dir: Path | None = None,
    ) -> None:
        # Resolve campaign directory — all output goes here
        if campaign_dir is not None:
            self._campaign_dir = campaign_dir
        elif config.resume and config.output_name is not None:
            # Resume: reuse existing campaign dir
            self._campaign_dir = Path(config.results_dir) / config.output_name
        else:
            # Generate new campaign dir name
            dir_name = config.output_name or self._generate_dir_name()
            self._campaign_dir = Path(config.results_dir) / dir_name
        self._campaign_dir.mkdir(parents=True, exist_ok=True)

        # Derived paths
        self._jsonl_path = self._campaign_dir / "campaign.jsonl"
        self._pcap_dir = self._campaign_dir / "pcap"
        self._crash_analysis_dir = self._campaign_dir / "crash_analysis"

        # Resume: restore original config from JSONL
        if config.resume and store is None and self._jsonl_path.exists():
            _tmp_store = ResultStore(self._jsonl_path)
            _checkpoint = _tmp_store.find_checkpoint()
            if _checkpoint is not None:
                _, _, _, _, _original_config = _checkpoint
                config = _original_config.model_copy(
                    update={
                        "resume": True,
                        "results_dir": config.results_dir,
                        "output_name": config.output_name,
                    }
                )

        self._config = config
        self._generator = generator or SIPGenerator(GeneratorSettings())
        self._mutator = mutator or SIPMutator()
        self._sender = sender or SIPSenderReactor()
        self._adb_collector: Any | None = None
        self._ios_collector: Any | None = None
        _docker_mode = config.mode == "real-ue-direct"
        if oracle is not None:
            self._oracle = oracle
        else:
            log_oracle = LogOracle() if config.log_path is not None else None
            adb_oracle = None
            ios_oracle = None

            if config.adb_enabled:
                from volte_mutation_fuzzer.adb.contracts import AdbCollectorConfig
                from volte_mutation_fuzzer.adb.core import (
                    AdbAnomalyDetector,
                    AdbLogCollector,
                )

                adb_cfg = AdbCollectorConfig(
                    serial=config.adb_serial,
                    buffers=config.adb_buffers,
                )
                adb_collector = AdbLogCollector(adb_cfg)
                adb_detector = AdbAnomalyDetector()
                adb_oracle = AdbOracle(adb_collector, adb_detector)
                self._adb_collector = adb_collector

            if config.ios_enabled:
                from volte_mutation_fuzzer.ios.contracts import IosCollectorConfig
                from volte_mutation_fuzzer.ios.core import (
                    IosAnomalyDetector,
                    IosSyslogCollector,
                )

                ios_cfg = IosCollectorConfig(
                    udid=config.ios_udid,
                    filter_processes=config.ios_filter_processes,
                )
                ios_collector = IosSyslogCollector(ios_cfg)
                ios_detector = IosAnomalyDetector()
                ios_oracle = IosOracle(ios_collector, ios_detector)
                self._ios_collector = ios_collector

            self._oracle = OracleEngine(
                log_oracle=log_oracle,
                adb_oracle=adb_oracle,
                ios_oracle=ios_oracle,
                docker_mode=_docker_mode,
            )
        self._store = store or ResultStore(self._jsonl_path)
        target_port = config.target_port
        if (
            config.mode == "real-ue-direct"
            and config.target_host is None
            and config.target_msisdn is not None
        ):
            target_port = None
        self._target = TargetEndpoint(
            host=config.target_host,
            port=target_port,
            transport=cast(TransportProtocol, config.transport),
            mode=cast(TargetMode, config.mode),
            timeout_seconds=config.timeout_seconds,
            msisdn=config.target_msisdn,
            ipsec_mode=config.ipsec_mode,
            source_ip=config.source_ip,
            bind_container=config.bind_container,
        )
        self._mt_template_text: str | None = (
            load_mt_invite_template(config.mt_invite_template)
            if config.mt_invite_template is not None
            else None
        )
        self._ue_resolver = RealUEDirectResolver()

        # Port cache for MT template path — avoids docker logs per case
        self._cached_ports: tuple[int, int] | None = None

        # Initialize crash analyzer
        self._crash_analyzer = CampaignCrashAnalyzer(
            output_dir=str(self._crash_analysis_dir),
            enabled=config.crash_analysis,
            source_name=str(self._jsonl_path),
        )

        # Initialize evidence collector
        self._evidence = EvidenceCollector(
            base_dir=self._campaign_dir,
        )

        # Call state checker for INVITE teardown verification
        self._call_state_checker: "CallStateChecker | None" = None
        if config.adb_enabled and config.mt_invite_template is not None:
            from volte_mutation_fuzzer.adb.call_state import CallStateChecker

            self._call_state_checker = CallStateChecker(
                serial=config.adb_serial,
            )

    @staticmethod
    def _generate_dir_name() -> str:
        return f"{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"

    @staticmethod
    def _case_wall_ms(case_started_monotonic: float) -> float:
        return round((time.monotonic() - case_started_monotonic) * 1000, 3)

    @property
    def campaign_dir(self) -> Path:
        return self._campaign_dir

    def run(self) -> CampaignResult:
        config = self._config
        skip_before = -1

        if config.resume:
            checkpoint = self._store.find_checkpoint()
            if checkpoint is not None:
                last_id, summary, campaign_id, started_at, _ = checkpoint
                skip_before = last_id
                self._store.write_resume_marker(last_id + 1)
                logger.info(
                    "resuming campaign %s from case_id=%d",
                    campaign_id,
                    last_id + 1,
                )
            else:
                # 파일 없거나 case 없음 → 새 캠페인처럼 시작
                campaign_id = uuid.uuid4().hex[:12]
                started_at = datetime.now(timezone.utc).isoformat()
                summary = CampaignSummary()
                _new_campaign = CampaignResult(
                    campaign_id=campaign_id,
                    started_at=started_at,
                    status="running",
                    config=config,
                    summary=summary,
                )
                self._store.write_header(_new_campaign)
        else:
            campaign_id = uuid.uuid4().hex[:12]
            started_at = datetime.now(timezone.utc).isoformat()
            summary = CampaignSummary()
            _new_campaign = CampaignResult(
                campaign_id=campaign_id,
                started_at=started_at,
                status="running",
                config=config,
                summary=summary,
            )
            self._store.write_header(_new_campaign)

        campaign = CampaignResult(
            campaign_id=campaign_id,
            started_at=started_at,
            status="running",
            config=config,
            summary=summary,
        )

        reporter = ConsoleProgressReporter(
            total_cases=config.max_cases,
            campaign_id=campaign_id,
            adb_enabled=bool(config.adb_enabled),
            pcap_enabled=bool(config.pcap_enabled),
            pcap_interface=config.pcap_interface,
        )

        if self._adb_collector is not None:
            self._adb_collector.start()
        if self._ios_collector is not None:
            self._ios_collector.start()
        self._capture_ios_baseline()
        consecutive_failures = 0
        cb_threshold = config.circuit_breaker_threshold
        # SA probe triggers at half the circuit breaker threshold (min 3)
        sa_probe_threshold = max(3, cb_threshold // 2) if cb_threshold > 0 else 0
        sa_checked_dead = False
        sa_probed_this_streak = False
        try:
            for spec in CaseGenerator(config).generate(skip_before=skip_before):
                case_result = self._execute_case(spec)

                # Circuit breaker: abort on consecutive timeout/unknown streaks
                if case_result.verdict in ("timeout", "unknown"):
                    consecutive_failures += 1
                    # Invalidate port cache — UE may have re-registered
                    self._cached_ports = None

                    # SA health probe: on sustained timeouts in real-ue-direct mode,
                    # check if IPsec SAs have expired.  If so, reclassify as
                    # infra_failure so the user knows this is not a real fuzz result.
                    # Only probe once per failure streak to avoid repeated docker exec.
                    if (
                        not sa_checked_dead
                        and not sa_probed_this_streak
                        and sa_probe_threshold > 0
                        and consecutive_failures >= sa_probe_threshold
                        and config.mode == "real-ue-direct"
                        and config.ipsec_mode is not None
                    ):
                        sa_probed_this_streak = True
                        sa_status = check_ipsec_sa_alive()
                        if not sa_status.alive:
                            sa_checked_dead = True
                            # Reclassify current verdict
                            case_result = case_result.model_copy(
                                update={
                                    "verdict": "infra_failure",
                                    "reason": f"IPsec SA expired ({sa_status.detail}); "
                                    f"original verdict: {case_result.verdict}",
                                }
                            )
                else:
                    consecutive_failures = 0
                    sa_checked_dead = False
                    sa_probed_this_streak = False

                self._store.append(case_result)

                # Real-time crash analysis
                self._analyze_case_result(case_result)

                self._update_summary(summary, case_result.verdict)

                # Console progress reporting
                adb_healthy: bool | None = None
                if (
                    self._adb_collector is not None
                    and hasattr(self._adb_collector, "is_healthy")
                ):
                    adb_healthy = self._adb_collector.is_healthy
                    if not adb_healthy:
                        dead = getattr(self._adb_collector, "dead_buffers", frozenset())
                        if dead:
                            reporter.on_adb_warning(dead)

                reporter.on_case_complete(
                    spec, case_result, summary, adb_healthy=adb_healthy
                )

                # SA expiry → immediate abort
                if sa_checked_dead:
                    reporter.on_circuit_breaker(
                        "IPsec SA expired — re-register the UE and restart."
                    )
                    logger.error("circuit breaker tripped: IPsec SA expired")
                    break

                if cb_threshold > 0 and consecutive_failures >= cb_threshold:
                    reporter.on_circuit_breaker(
                        f"{consecutive_failures} consecutive timeout/unknown verdicts"
                    )
                    logger.error(
                        "circuit breaker tripped after %d consecutive failures",
                        consecutive_failures,
                    )
                    break

                if config.cooldown_seconds > 0:
                    time.sleep(config.cooldown_seconds)

        except KeyboardInterrupt:
            campaign = campaign.model_copy(
                update={
                    "status": "aborted",
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "summary": summary,
                }
            )
            self._store.write_footer(campaign)
            reporter.finalize(summary, "aborted")
            try:
                HtmlReportGenerator(self._jsonl_path).generate()
            except Exception:
                pass
            return campaign
        finally:
            if self._adb_collector is not None:
                self._adb_collector.stop()
            if self._ios_collector is not None:
                self._ios_collector.stop()

            # Generate final crash analysis report
            self._finalize_crash_analysis()
            self._wait_for_pending_pcap_exports()

        final_status = (
            "aborted"
            if sa_checked_dead or (cb_threshold > 0 and consecutive_failures >= cb_threshold)
            else "completed"
        )
        campaign = campaign.model_copy(
            update={
                "status": final_status,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "summary": summary,
            }
        )
        self._store.write_footer(campaign)
        reporter.finalize(summary, final_status)

        # Generate HTML report
        try:
            report_path = HtmlReportGenerator(self._jsonl_path).generate()
            print(f"[vmf campaign] report: {report_path}", file=sys.stderr)
        except Exception as exc:
            logger.warning("failed to generate HTML report: %s", exc)

        return campaign

    def _wait_for_pending_pcap_exports(self) -> None:
        try:
            PcapCapture.wait_for_pending_exports()
        except Exception as exc:
            logger.warning("failed to drain pending pcap txt exports: %s", exc)

    def _dialog_scenario_for_runtime_method(self, method: str):
        completion = get_packet_completion(SIPMethod(method))
        if completion.tier is not PacketCompletionTier.runtime_complete:
            return None
        if completion.runtime_path not in _DIALOG_RUNTIME_PATHS:
            return None
        return scenario_for_method(method)

    def _execute_case(self, spec: CaseSpec) -> CaseResult:
        config = self._config
        timestamp = time.time()
        case_started_monotonic = time.monotonic()
        error: str | None = None
        capture: PcapCapture | None = None
        pcap_path_saved: str | None = None
        mutated: MutatedCase | None = None

        try:
            scenario = None
            if spec.response_code is None:
                scenario = self._dialog_scenario_for_runtime_method(spec.method)
                if scenario is not None:
                    return self._execute_dialog_case(
                        spec, scenario, timestamp, case_started_monotonic
                    )

            # MT template path (real-ue-direct with 3GPP format)
            if (
                self._mt_template_text is not None
                and spec.response_code is None
            ):
                return self._execute_mt_template_case(
                    spec, timestamp, case_started_monotonic
                )

            packet = self._build_packet(spec)
            mutated = self._mutator.mutate(
                packet,
                MutationConfig(
                    seed=spec.seed,
                    profile=spec.profile,
                    strategy=spec.strategy,
                    layer=cast(Literal["model", "wire", "byte", "auto"], spec.layer),
                ),
            )
            artifact = self._artifact_from_mutated(mutated)
            sent_payload: str | bytes | None = artifact.wire_text or artifact.packet_bytes
            if config.pcap_enabled:
                pcap_dir = self._pcap_dir
                pcap_dir.mkdir(parents=True, exist_ok=True)
                pcap_path = str(pcap_dir / f"case_{spec.case_id:06d}.pcap")
                capture = PcapCapture(pcap_path, interface=config.pcap_interface)
                capture.start()
            try:
                send_result = self._sender.send_artifact(
                    artifact, self._target, collect_all_responses=(spec.method == "INVITE")
                )
            finally:
                if capture is not None:
                    pcap_path_saved = capture.stop()

            context = OracleContext(
                method=spec.related_method or spec.method,
                timeout_threshold_ms=config.timeout_seconds * 1000,
                log_grace_seconds=config.oracle_log_grace_seconds_for_method(
                    spec.related_method or spec.method
                ),
            )
            process_name = config.process_name if config.check_process else None
            verdict = self._oracle.evaluate(
                send_result,
                context,
                process_name=process_name,
                log_path=config.log_path,
                process_check_interval=10,
            )
            mutation_ops = tuple(
                f"{r.operator}({r.target.path})" for r in mutated.records
            )
            resolved_profile = getattr(mutated, "profile", spec.profile)
            resolved_strategy = getattr(mutated, "strategy", spec.strategy)
            raw_response = self._raw_response_from_send_result(
                verdict.verdict, send_result
            )
            case_result = self._build_case_result(
                spec,
                verdict=verdict.verdict,
                reason=verdict.reason,
                response_code=verdict.response_code,
                elapsed_ms=verdict.elapsed_ms,
                process_alive=verdict.process_alive,
                raw_response=raw_response,
                reproduction_cmd=self._build_reproduction_cmd(
                    spec,
                    profile=resolved_profile,
                    strategy=resolved_strategy,
                ),
                profile=resolved_profile,
                strategy=resolved_strategy,
                mutation_ops=mutation_ops,
                error=error,
                details=getattr(verdict, "details", {}) or {},
                timestamp=timestamp,
                fuzz_response_code=spec.response_code,
                fuzz_related_method=spec.related_method,
                pcap_path=pcap_path_saved,
                # Finalize after evidence.collect() so the metric includes persistence time.
                case_wall_ms=0.0,
            )

            return self._persist_case_artifacts(
                spec,
                case_result,
                sent_payload=sent_payload,
                timestamp=timestamp,
                case_started_monotonic=case_started_monotonic,
            )

        except Exception as exc:
            error = str(exc)
            resolved_profile = getattr(mutated, "profile", spec.profile)
            resolved_strategy = getattr(mutated, "strategy", spec.strategy)
            return self._build_case_result(
                spec,
                verdict="unknown",
                reason=f"executor error: {error}",
                elapsed_ms=0.0,
                reproduction_cmd=self._build_reproduction_cmd(
                    spec,
                    profile=resolved_profile,
                    strategy=resolved_strategy,
                ),
                profile=resolved_profile,
                strategy=resolved_strategy,
                error=error,
                timestamp=timestamp,
                fuzz_response_code=spec.response_code,
                fuzz_related_method=spec.related_method,
                pcap_path=pcap_path_saved,
                case_wall_ms=self._case_wall_ms(case_started_monotonic),
            )

    def _resolve_ports_cached(self, msisdn: str) -> tuple[int, int]:
        """Return cached (port_pc, port_ps) or resolve and cache them."""
        if self._cached_ports is not None:
            return self._cached_ports
        ports = self._ue_resolver.resolve_protected_ports(msisdn)
        self._cached_ports = ports
        return ports

    def _teardown_invite(
        self,
        wire_text: str,
        mt_target: TargetEndpoint,
        send_result: SendReceiveResult,
        config: CampaignConfig,
    ) -> list[str]:
        """Send CANCEL to tear down an INVITE session with retry on failure.

        RFC 3261 §9.1: CANCEL should only be sent after receiving a
        provisional response.  We check whether any 1xx was received and
        skip CANCEL entirely if none (the server never created transaction
        state, so there is nothing to cancel).

        Returns a list of observer events describing teardown outcome.
        """
        events: list[str] = []

        # Check if we received at least one provisional response (1xx).
        has_provisional = any(
            obs.status_code is not None and 100 <= obs.status_code < 200
            for obs in send_result.responses
        )
        has_final = any(
            obs.status_code is not None and obs.status_code >= 200
            for obs in send_result.responses
        )

        if not has_provisional and not has_final:
            # No response at all (timeout) — server never saw the INVITE or
            # didn't create transaction state.  CANCEL would be meaningless.
            events.append("teardown:skipped:no-response")
            return events

        if has_final and not has_provisional:
            # Got a final response without provisional (e.g. 486 Busy).
            # Transaction is already terminated — no CANCEL needed.
            events.append("teardown:skipped:final-only")
            return events

        # Build CANCEL from the actual INVITE wire text that was sent.
        cancel_text = re.sub(r"^INVITE\b", "CANCEL", wire_text, count=1)
        cancel_text = re.sub(
            r"(?m)^(CSeq:\s*\d+)\s+INVITE\b",
            r"\1 CANCEL",
            cancel_text,
            count=1,
        )
        cancel_artifact = SendArtifact(
            wire_text=cancel_text,
            preserve_via=config.preserve_via,
            preserve_contact=config.preserve_contact,
        )

        teardown_ok = False
        for attempt in range(_CANCEL_MAX_RETRIES):
            try:
                cancel_result = self._sender.send_artifact(
                    cancel_artifact, mt_target, collect_all_responses=True
                )
                # 200 OK to CANCEL or 487 Request Terminated means success.
                for obs in cancel_result.responses:
                    if obs.status_code in (200, 487):
                        teardown_ok = True
                        break
                if teardown_ok:
                    events.append(
                        f"teardown:cancel-ok:attempt={attempt + 1}"
                        f":code={obs.status_code}"
                    )
                    break
                # Got a response but not 200/487 — retry.
                events.append(
                    f"teardown:cancel-unexpected:attempt={attempt + 1}"
                    f":codes={[o.status_code for o in cancel_result.responses]}"
                )
            except Exception as exc:
                events.append(
                    f"teardown:cancel-error:attempt={attempt + 1}:{exc}"
                )

            if attempt < _CANCEL_MAX_RETRIES - 1:
                time.sleep(_CANCEL_RETRY_INTERVAL)

        if not teardown_ok:
            events.append(
                f"teardown:cancel-failed:after={_CANCEL_MAX_RETRIES}-attempts"
            )
            # Extra cooldown to let the device's own timer expire the session.
            time.sleep(_CANCEL_TEARDOWN_TIMEOUT)

        return events

    def _execute_mt_template_case(
        self,
        spec: CaseSpec,
        timestamp: float,
        case_started_monotonic: float,
    ) -> CaseResult:
        """Execute one MT INVOKE replay-template case against a real UE."""
        config = self._config
        assert self._mt_template_text is not None
        assert config.target_msisdn is not None

        error: str | None = None
        capture: PcapCapture | None = None
        pcap_path_saved: str | None = None
        mutated_wire: MutatedWireCase | None = None

        try:
            # 1. Resolve UE IP and IMPI dynamically
            ue_ip = config.target_host
            impi = config.impi
            if ue_ip is None:
                resolved = self._ue_resolver.resolve(self._target, impi=impi)
                ue_ip = resolved.host
                if impi is None and resolved.impi is not None:
                    impi = resolved.impi

            if impi is None:
                raise ValueError(
                    "IMPI could not be determined. Specify --impi or set VMF_IMPI"
                )

            # 2. Resolve live port_pc / port_ps (cached)
            port_pc, port_ps = self._resolve_ports_cached(config.target_msisdn)

            # 3. Build wire text
            pcscf_ip = os.environ.get("VMF_REAL_UE_PCSCF_IP", _DEFAULT_PCSCF_IP)

            if spec.method == "INVITE":
                # INVITE uses the proven file-based template
                slots = build_default_slots(
                    msisdn=config.target_msisdn,
                    impi=impi,
                    pcscf_ip=pcscf_ip,
                    port_pc=port_pc,
                    port_ps=port_ps,
                    mo_contact_host=config.mo_contact_host,
                    mo_contact_port_pc=config.mo_contact_port_pc,
                    mo_contact_port_ps=config.mo_contact_port_ps,
                    seed=spec.seed,
                    from_msisdn=config.from_msisdn,
                    ue_ip=ue_ip,
                    local_port=config.mt_local_port,
                )
                wire_text = render_mt_invite(self._mt_template_text, slots)
            else:
                # All other methods use the generic 3GPP builder
                from volte_mutation_fuzzer.generator.mt_packet import build_mt_packet
                wire_text = build_mt_packet(
                    method=spec.method,
                    impi=impi,
                    msisdn=config.target_msisdn,
                    ue_ip=ue_ip,
                    port_pc=port_pc,
                    port_ps=port_ps,
                    seed=spec.seed,
                    local_port=config.mt_local_port,
                    from_msisdn=config.from_msisdn,
                )

            # 4. Fragmentation guard (plaintext UDP, host-direct only)
            # bypass 모드(Docker 내부망)는 IP fragmentation이 허용된다.
            # null 모드(호스트 직접)는 실제 LTE 경로로 가므로 fragmentation 제한 필요.
            if (
                self._target.transport.upper() == "UDP"
                and config.ipsec_mode == "null"
                and len(wire_text.encode("utf-8")) > _MT_TEMPLATE_FRAG_LIMIT
            ):
                return self._build_case_result(
                    spec,
                    verdict="unknown",
                    reason=(
                        f"template payload exceeds one-fragment UDP safety threshold "
                        f"({_MT_TEMPLATE_FRAG_LIMIT} bytes)"
                    ),
                    elapsed_ms=0.0,
                    reproduction_cmd=self._build_mt_template_reproduction_cmd(
                        spec,
                        profile=spec.profile,
                        strategy=spec.strategy,
                    ),
                    error="fragmentation-guard",
                    timestamp=timestamp,
                    case_wall_ms=self._case_wall_ms(case_started_monotonic),
                )

            # 5. Parse to EditableSIPMessage
            editable = parse_editable_from_wire(wire_text)

            # 6. Determine effective layer (model → downgrade to wire)
            effective_layer = spec.layer
            if effective_layer == "model":
                effective_layer = "wire"

            # 7. Mutate
            mutated_wire = self._mutator.mutate_editable(
                editable,
                MutationConfig(
                    seed=spec.seed,
                    profile=spec.profile,
                    strategy=spec.strategy,
                    layer=cast(
                        Literal["model", "wire", "byte", "auto"], effective_layer
                    ),
                ),
            )

            # 8. Build SendArtifact
            if mutated_wire.final_layer == "wire" and mutated_wire.wire_text is not None:
                artifact = SendArtifact(
                    wire_text=mutated_wire.wire_text,
                    preserve_via=config.preserve_via,
                    preserve_contact=config.preserve_contact,
                )
            else:
                assert mutated_wire.packet_bytes is not None
                artifact = SendArtifact(
                    packet_bytes=mutated_wire.packet_bytes,
                    preserve_via=config.preserve_via,
                    preserve_contact=config.preserve_contact,
                )
            sent_payload: str | bytes | None = artifact.wire_text or artifact.packet_bytes

            # 9. pcap + send
            # 실제 송신은 port_pc로 간다. Plaintext UDP 경로라 ESP 정책 매칭이
            # 아닌 단순 UDP 수신 포트가 port_pc다. bind_port는 슬롯에 주입한
            # Via sent-by와 동일해야 응답 수신 가능하다.

            # ipsec_mode에 따라 송신 방식 결정
            target_update = {
                "host": ue_ip,
                "port": port_pc,
                "ipsec_mode": config.ipsec_mode,
                "source_ip": None,
                "bind_container": "pcscf",
                "bind_port": None
                if config.ipsec_mode == "native"
                else config.mt_local_port,
            }

            mt_target = self._target.model_copy(update=target_update)
            if config.pcap_enabled:
                pcap_dir = self._pcap_dir
                pcap_dir.mkdir(parents=True, exist_ok=True)
                pcap_path = str(pcap_dir / f"case_{spec.case_id:06d}.pcap")
                # MT packets use dynamic ports (port_pc/mt_local_port), not 5060
                pcap_filter = f"host {ue_ip}"
                capture = PcapCapture(
                    pcap_path,
                    interface=config.pcap_interface,
                    filter_expr=pcap_filter,
                )
                capture.start()
            is_invite = spec.method == "INVITE"
            try:
                send_result = self._sender.send_artifact(
                    artifact, mt_target, collect_all_responses=is_invite
                )
            finally:
                if capture is not None:
                    pcap_path_saved = capture.stop()

            sent_wire_text = self._artifact_wire_text(artifact) or wire_text

            # 9b. Reliable CANCEL teardown (INVITE only)
            if is_invite:
                teardown_events = self._teardown_invite(
                    sent_wire_text, mt_target, send_result, config
                )
                for te in teardown_events:
                    logger.info("case %s: %s", spec.case_id, te)

            # 9c. Wait for device to return to IDLE call state (INVITE only)
            if is_invite and self._call_state_checker is not None:
                idle_events = self._call_state_checker.wait_for_idle()
                for ie in idle_events:
                    logger.info("case %s: %s", spec.case_id, ie)

            # 10. Oracle
            context = OracleContext(
                method=spec.method,
                timeout_threshold_ms=config.timeout_seconds * 1000,
                log_grace_seconds=config.oracle_log_grace_seconds_for_method(
                    spec.method
                ),
            )
            process_name = config.process_name if config.check_process else None
            verdict = self._oracle.evaluate(
                send_result,
                context,
                process_name=process_name,
                log_path=config.log_path,
                process_check_interval=10,
            )

            mutation_ops = tuple(
                f"{r.operator}({r.target.path})" for r in mutated_wire.records
            )
            resolved_profile = getattr(mutated_wire, "profile", spec.profile)
            resolved_strategy = getattr(mutated_wire, "strategy", spec.strategy)
            raw_response = self._raw_response_from_send_result(
                verdict.verdict, send_result
            )
            case_result = self._build_case_result(
                spec,
                verdict=verdict.verdict,
                reason=verdict.reason,
                response_code=verdict.response_code,
                elapsed_ms=verdict.elapsed_ms,
                process_alive=verdict.process_alive,
                raw_response=raw_response,
                reproduction_cmd=self._build_mt_template_reproduction_cmd(
                    spec,
                    profile=resolved_profile,
                    strategy=resolved_strategy,
                ),
                profile=resolved_profile,
                strategy=resolved_strategy,
                mutation_ops=mutation_ops,
                error=error,
                details=getattr(verdict, "details", {}) or {},
                timestamp=timestamp,
                fuzz_response_code=spec.response_code,
                fuzz_related_method=spec.related_method,
                pcap_path=pcap_path_saved,
                # Finalize after evidence.collect() so the metric includes persistence time.
                case_wall_ms=0.0,
            )

            return self._persist_case_artifacts(
                spec,
                case_result,
                sent_payload=sent_payload,
                timestamp=timestamp,
                case_started_monotonic=case_started_monotonic,
            )

        except Exception as exc:
            error = str(exc)
            resolved_profile = getattr(mutated_wire, "profile", spec.profile)
            resolved_strategy = getattr(mutated_wire, "strategy", spec.strategy)
            return self._build_case_result(
                spec,
                verdict="unknown",
                reason=f"mt-template executor error: {error}",
                elapsed_ms=0.0,
                reproduction_cmd=self._build_mt_template_reproduction_cmd(
                    spec,
                    profile=resolved_profile,
                    strategy=resolved_strategy,
                ),
                profile=resolved_profile,
                strategy=resolved_strategy,
                error=error,
                timestamp=timestamp,
                fuzz_response_code=spec.response_code,
                fuzz_related_method=spec.related_method,
                pcap_path=pcap_path_saved,
                case_wall_ms=self._case_wall_ms(case_started_monotonic),
            )

    def _build_mt_template_reproduction_cmd(
        self,
        spec: CaseSpec,
        *,
        profile: str | None = None,
        strategy: str | None = None,
    ) -> str:
        cfg = self._config
        target_args = ""
        if cfg.target_host is not None:
            target_args = f" --target-host {cfg.target_host}"
        elif cfg.target_msisdn is not None:
            target_args = f" --target-msisdn {cfg.target_msisdn}"
        profile_value = spec.profile if profile is None else profile
        strategy_value = spec.strategy if strategy is None else strategy

        reproduction_cmd = (
            f"uv run fuzzer campaign run"
            f" --mode real-ue-direct"
            f"{target_args}"
            f" --impi {cfg.impi}"
            f" --mt-invite-template {cfg.mt_invite_template}"
            f" --ipsec-mode {cfg.ipsec_mode}"
            f"{' --preserve-via' if cfg.preserve_via else ''}"
            f"{' --preserve-contact' if cfg.preserve_contact else ''}"
            f" --methods {spec.method}"
            f" --profile {profile_value}"
            f" --layer {spec.layer}"
            f" --strategy {strategy_value}"
            f" --seed-start {spec.seed}"
            f" --max-cases 1"
            # note: port_pc/port_ps are re-queried live; may differ if UE re-registered
        )
        if cfg.ipsec_mode != "native":
            reproduction_cmd += f" --mt-local-port {cfg.mt_local_port}"
        return reproduction_cmd

    def _artifact_wire_text(self, artifact: SendArtifact) -> str | None:
        if artifact.wire_text is not None:
            return artifact.wire_text
        if artifact.packet is not None:
            return render_packet(artifact.packet)
        if artifact.packet_bytes is not None:
            return artifact.packet_bytes.decode("utf-8", errors="replace")
        return None

    def _build_replay_target_args(self) -> str:
        cfg = self._config
        if cfg.mode == "real-ue-direct":
            if cfg.target_msisdn is not None:
                return f" --target-msisdn {cfg.target_msisdn}"
            if cfg.target_host is not None:
                return f" --target-host {cfg.target_host}"
            return ""
        if cfg.target_host is not None:
            return f" --target-host {cfg.target_host}"
        return ""

    def _execute_dialog_case(
        self,
        spec: CaseSpec,
        scenario,
        timestamp: float,
        case_started_monotonic: float,
    ) -> CaseResult:
        orchestrator = DialogOrchestrator(self._generator, self._mutator, self._target)
        mutation_config = MutationConfig(
            seed=spec.seed,
            profile=spec.profile,
            strategy=spec.strategy,
            layer=cast(Literal["model", "wire", "byte", "auto"], spec.layer),
        )
        config = self._config
        capture: PcapCapture | None = None
        pcap_path_saved: str | None = None
        try:
            if config.pcap_enabled:
                pcap_dir = self._pcap_dir
                pcap_dir.mkdir(parents=True, exist_ok=True)
                pcap_path = str(pcap_dir / f"case_{spec.case_id:06d}.pcap")
                capture = PcapCapture(pcap_path, interface=config.pcap_interface)
                capture.start()
            try:
                exchange = orchestrator.execute(scenario, mutation_config)
            finally:
                if capture is not None:
                    pcap_path_saved = capture.stop()
        except Exception as exc:
            return self._build_case_result(
                spec,
                verdict="unknown",
                reason=f"dialog executor error: {exc}",
                elapsed_ms=0.0,
                reproduction_cmd=self._build_reproduction_cmd(spec),
                error=str(exc),
                timestamp=timestamp,
                pcap_path=pcap_path_saved,
                case_wall_ms=self._case_wall_ms(case_started_monotonic),
            )

        if not exchange.setup_succeeded:
            return self._build_case_result(
                spec,
                verdict="unknown",
                reason=f"dialog setup failed: {exchange.error or 'unknown'}",
                elapsed_ms=0.0,
                reproduction_cmd=self._build_reproduction_cmd(spec),
                error=exchange.error,
                timestamp=timestamp,
                pcap_path=pcap_path_saved,
                case_wall_ms=self._case_wall_ms(case_started_monotonic),
            )

        fuzz_result = exchange.fuzz_result
        send_result = fuzz_result.send_result if fuzz_result is not None else None
        resolved_profile = (
            getattr(fuzz_result, "profile", spec.profile)
            if fuzz_result is not None
            else spec.profile
        )
        resolved_strategy = (
            getattr(fuzz_result, "strategy", spec.strategy)
            if fuzz_result is not None
            else spec.strategy
        )

        if send_result is None:
            return self._build_case_result(
                spec,
                verdict="unknown",
                reason="dialog fuzz step produced no send result",
                elapsed_ms=0.0,
                reproduction_cmd=self._build_reproduction_cmd(
                    spec,
                    profile=resolved_profile,
                    strategy=resolved_strategy,
                ),
                profile=resolved_profile,
                strategy=resolved_strategy,
                timestamp=timestamp,
                pcap_path=pcap_path_saved,
                case_wall_ms=self._case_wall_ms(case_started_monotonic),
            )

        context = OracleContext(
            method=spec.method,
            timeout_threshold_ms=config.timeout_seconds * 1000,
            log_grace_seconds=config.oracle_log_grace_seconds_for_method(
                spec.method
            ),
        )
        process_name = config.process_name if config.check_process else None
        verdict = self._oracle.evaluate(
            send_result,
            context,
            process_name=process_name,
            log_path=config.log_path,
            process_check_interval=10,
        )

        raw_response = self._raw_response_from_send_result(verdict.verdict, send_result)

        case_result = self._build_case_result(
            spec,
            verdict=verdict.verdict,
            reason=verdict.reason,
            response_code=verdict.response_code,
            elapsed_ms=verdict.elapsed_ms,
            process_alive=verdict.process_alive,
            raw_response=raw_response,
            reproduction_cmd=self._build_reproduction_cmd(
                spec,
                profile=resolved_profile,
                strategy=resolved_strategy,
            ),
            profile=resolved_profile,
            strategy=resolved_strategy,
            details=getattr(verdict, "details", {}) or {},
            timestamp=timestamp,
            pcap_path=pcap_path_saved,
            case_wall_ms=0.0,
        )

        return self._persist_case_artifacts(
            spec,
            case_result,
            sent_payload=None,
            timestamp=timestamp,
            case_started_monotonic=case_started_monotonic,
        )

    def _build_packet(self, spec: CaseSpec) -> PacketModel:
        if spec.response_code is None:
            context = (
                self._synthetic_dialog_context() if self._config.with_dialog else None
            )
            return self._generator.generate_request(
                RequestSpec(method=SIPMethod(spec.method)),
                context,
            )

        related_method = SIPMethod(spec.related_method or spec.method)
        return self._generator.generate_response(
            ResponseSpec(
                status_code=spec.response_code,
                related_method=related_method,
            ),
            self._synthetic_dialog_context(),
        )

    def _synthetic_dialog_context(self) -> DialogContext:
        return DialogContext(
            call_id=f"campaign-{uuid.uuid4().hex}",
            local_tag="campaign-local",
            remote_tag="campaign-remote",
            local_cseq=1,
            remote_cseq=1,
            request_uri=SIPURI(
                user="target",
                host=self._target.host,
                port=self._target.port,
            ),
        )

    def _artifact_from_mutated(self, mutated: MutatedCase) -> SendArtifact:
        if mutated.final_layer == "wire" and mutated.wire_text is not None:
            return SendArtifact.from_wire_text(mutated.wire_text)
        if mutated.final_layer == "byte" and mutated.packet_bytes is not None:
            return SendArtifact.from_packet_bytes(mutated.packet_bytes)
        packet = mutated.mutated_packet or mutated.original_packet
        return SendArtifact.from_packet(packet)

    def _build_case_result(
        self,
        spec: CaseSpec,
        *,
        verdict: str,
        reason: str,
        elapsed_ms: float,
        reproduction_cmd: str | None = None,
        profile: str | None = None,
        strategy: str | None = None,
        mutation_ops: tuple[str, ...] = (),
        response_code: int | None = None,
        process_alive: bool | None = None,
        raw_response: str | None = None,
        error: str | None = None,
        details: dict[str, object] | None = None,
        timestamp: float,
        fuzz_response_code: int | None = None,
        fuzz_related_method: str | None = None,
        pcap_path: str | None = None,
        case_wall_ms: float | None = None,
    ) -> CaseResult:
        resolved_profile = spec.profile if profile is None else profile
        resolved_strategy = spec.strategy if strategy is None else strategy
        resolved_reproduction_cmd = (
            reproduction_cmd
            if reproduction_cmd is not None
            else self._build_reproduction_cmd(
                spec,
                profile=resolved_profile,
                strategy=resolved_strategy,
            )
        )
        return CaseResult(
            case_id=spec.case_id,
            seed=spec.seed,
            method=spec.method,
            profile=resolved_profile,
            layer=spec.layer,
            strategy=resolved_strategy,
            mutation_ops=mutation_ops,
            verdict=verdict,
            reason=reason,
            response_code=response_code,
            elapsed_ms=elapsed_ms,
            process_alive=process_alive,
            raw_response=raw_response,
            reproduction_cmd=resolved_reproduction_cmd,
            error=error,
            details=details or {},
            timestamp=timestamp,
            fuzz_response_code=fuzz_response_code,
            fuzz_related_method=fuzz_related_method,
            pcap_path=pcap_path,
            case_wall_ms=case_wall_ms,
        )

    def _build_reproduction_cmd(
        self,
        spec: CaseSpec,
        *,
        profile: str | None = None,
        strategy: str | None = None,
    ) -> str:
        cfg = self._config
        target_args = self._build_replay_target_args()
        transport_arg = (
            f" --transport {cfg.transport}" if cfg.transport.upper() != "UDP" else ""
        )
        ipsec_arg = f" --ipsec-mode {cfg.ipsec_mode}" if cfg.ipsec_mode else ""
        profile_value = spec.profile if profile is None else profile
        strategy_value = spec.strategy if strategy is None else strategy
        if spec.response_code is not None:
            context = json.dumps(
                self._synthetic_dialog_context().model_dump(mode="json"),
                ensure_ascii=False,
            )
            related_method = spec.related_method or spec.method
            return (
                f"uv run fuzzer mutate response {spec.response_code} {related_method}"
                f" --context '{context}'"
                f" --profile {profile_value}"
                f" --strategy {strategy_value}"
                f" --layer {spec.layer}"
                f" --seed {spec.seed}"
                f" | uv run fuzzer send packet"
                f" --mode {cfg.mode}"
                f"{target_args}"
                f" --target-port {cfg.target_port}"
                f"{transport_arg}"
                f"{ipsec_arg}"
            )
        return (
            f"uv run fuzzer mutate request {spec.method}"
            f" --profile {profile_value}"
            f" --strategy {strategy_value}"
            f" --layer {spec.layer}"
            f" --seed {spec.seed}"
            f" | uv run fuzzer send packet"
            f" --mode {cfg.mode}"
            f"{target_args}"
            f" --target-port {cfg.target_port}"
            f"{transport_arg}"
            f"{ipsec_arg}"
        )

    @staticmethod
    def _update_summary(summary: CampaignSummary, verdict: str) -> None:
        summary.total += 1
        match verdict:
            case "normal":
                summary.normal += 1
            case "suspicious":
                summary.suspicious += 1
            case "timeout":
                summary.timeout += 1
            case "crash":
                summary.crash += 1
            case "stack_failure":
                summary.stack_failure += 1
            case "infra_failure":
                summary.infra_failure += 1
            case _:
                summary.unknown += 1

    @staticmethod
    def _snapshot_profile_for_verdict(verdict: str) -> Literal["light", "full"]:
        if verdict in ("suspicious", "crash", "stack_failure"):
            return "full"
        return "light"

    def _capture_adb_snapshot(
        self,
        spec: CaseSpec,
        *,
        timestamp: float,
        verdict: str,
        snapshot_until: float | None = None,
    ) -> str | None:
        config = self._config
        if not config.adb_enabled:
            return None

        try:
            from volte_mutation_fuzzer.adb.core import AdbConnector

            snapshot_until = snapshot_until if snapshot_until is not None else time.time()
            adb_snapshot_dir = str(
                self._campaign_dir / "adb_snapshots" / f"case_{spec.case_id}"
            )
            AdbConnector(serial=config.adb_serial).take_snapshot(
                adb_snapshot_dir,
                collector=self._adb_collector,
                log_since=timestamp,
                log_until=snapshot_until,
                profile=self._snapshot_profile_for_verdict(verdict),
            )
            return adb_snapshot_dir
        except Exception as exc:
            logger.warning(
                "failed to capture adb snapshot for case %s: %s",
                spec.case_id,
                exc,
            )
            return None

    def _capture_ios_baseline(self) -> None:
        config = self._config
        if not config.ios_enabled:
            return

        try:
            from volte_mutation_fuzzer.ios.core import IosConnector

            baseline_dir = self._campaign_dir / "ios_baseline"
            baseline_dir.mkdir(parents=True, exist_ok=True)
            device_info_path = baseline_dir / "device_info.json"
            if device_info_path.exists():
                return

            info = IosConnector(udid=config.ios_udid).check_device()
            payload = info.model_dump(mode="json")
            payload["captured_at"] = datetime.now(timezone.utc).isoformat()
            device_info_path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        except Exception as exc:
            logger.warning("failed to capture ios baseline: %s", exc)

    def _capture_ios_snapshot(
        self,
        spec: CaseSpec,
        *,
        timestamp: float,
        snapshot_until: float | None = None,
    ) -> str | None:
        config = self._config
        if not config.ios_enabled or self._ios_collector is None:
            return None

        try:
            from volte_mutation_fuzzer.ios.core import IosAnomalyDetector, IosConnector

            snapshot_until = snapshot_until if snapshot_until is not None else time.time()
            ios_snapshot_dir = str(
                self._campaign_dir / "ios_snapshots" / f"case_{spec.case_id}"
            )
            IosConnector(udid=config.ios_udid).take_snapshot(
                ios_snapshot_dir,
                collector=self._ios_collector,
                syslog_since=timestamp,
                syslog_until=snapshot_until,
                detector=IosAnomalyDetector(),
                run_diagnostics=config.ios_run_diagnostics,
            )
            return ios_snapshot_dir
        except Exception as exc:
            logger.warning(
                "failed to capture ios snapshot for case %s: %s",
                spec.case_id,
                exc,
            )
            return None

    def _persist_case_artifacts(
        self,
        spec: CaseSpec,
        case_result: CaseResult,
        *,
        sent_payload: str | bytes | None,
        timestamp: float,
        case_started_monotonic: float,
    ) -> CaseResult:
        snapshot_until = time.time()
        adb_snapshot_dir = self._capture_adb_snapshot(
            spec,
            timestamp=timestamp,
            verdict=case_result.verdict,
            snapshot_until=snapshot_until,
        )
        ios_snapshot_dir = self._capture_ios_snapshot(
            spec,
            timestamp=timestamp,
            snapshot_until=snapshot_until,
        )
        self._evidence.collect(
            case_result,
            sent_payload=sent_payload,
            pcap_path=case_result.pcap_path,
            adb_snapshot_dir=adb_snapshot_dir,
            ios_snapshot_dir=ios_snapshot_dir,
        )
        return case_result.model_copy(
            update={"case_wall_ms": self._case_wall_ms(case_started_monotonic)}
        )

    def _raw_response_from_send_result(
        self, verdict: str, send_result: SendReceiveResult
    ) -> str | None:
        final_response = send_result.final_response
        if final_response is None:
            return None
        if self._config.ipsec_mode == "native":
            return final_response.raw_text or None
        if verdict in ("suspicious", "crash", "stack_failure"):
            return final_response.raw_text or None
        return None

    def _analyze_case_result(self, case_result: CaseResult) -> None:
        try:
            self._crash_analyzer.analyze_case_immediately(case_result)
        except Exception as exc:
            logger.warning(
                "crash analysis failed for case %s: %s",
                case_result.case_id,
                exc,
            )

    def _finalize_crash_analysis(self) -> None:
        try:
            self._crash_analyzer.generate_final_report()
        except Exception as exc:
            logger.warning("failed to generate crash analysis report: %s", exc)
