import logging
import json
import os
import sys
import time
import uuid
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

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
from volte_mutation_fuzzer.mutator.contracts import MutationConfig, MutatedCase
from volte_mutation_fuzzer.mutator.core import SIPMutator
from volte_mutation_fuzzer.mutator.editable import parse_editable_from_wire
from volte_mutation_fuzzer.oracle.contracts import OracleContext
from volte_mutation_fuzzer.oracle.core import AdbOracle, LogOracle, OracleEngine
from volte_mutation_fuzzer.sender.contracts import (
    SendArtifact,
    TargetEndpoint,
)
from volte_mutation_fuzzer.sender.core import SIPSenderReactor
from volte_mutation_fuzzer.sender.real_ue import RealUEDirectResolver, check_ipsec_sa_alive
from volte_mutation_fuzzer.sip.catalog import SIP_CATALOG
from volte_mutation_fuzzer.sip.common import SIPMethod, SIPURI
from volte_mutation_fuzzer.analysis.crash_analyzer import CampaignCrashAnalyzer

_DEFAULT_PCSCF_IP: str = "172.22.0.21"
_MT_TEMPLATE_FRAG_LIMIT: int = 65535  # bytes; raised — Docker bridge IP reassembly works fine in practice

logger = logging.getLogger(__name__)


# layer별 지원 전략 매핑 — mutator/core.py _validate_supported_strategy와 동기화
_SUPPORTED_STRATEGIES: dict[str, frozenset[str]] = {
    "model": frozenset({"default", "state_breaker"}),
    "wire": frozenset({"default", "identity"}),
    "byte": frozenset({"default", "identity"}),
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
        seen: set[tuple[str, int | None, str | None, str, str]] = set()
        combos: list[tuple[str, int | None, str | None, str, str]] = []

        # Template mode: inject identity-baseline case as case 0, drop model layer
        template_active = config.mt_invite_template is not None
        if template_active:
            identity_key = ("INVITE", None, None, "wire", "identity")
            seen.add(identity_key)
            combos.append(identity_key)

        effective_layers = (
            tuple(lyr for lyr in config.layers if lyr != "model")
            if template_active
            else config.layers
        )

        for method in config.methods:
            for layer in effective_layers:
                for strategy in config.strategies:
                    if strategy not in _SUPPORTED_STRATEGIES.get(layer, frozenset()):
                        continue
                    key = (method, None, None, layer, strategy)
                    if key not in seen:
                        seen.add(key)
                        combos.append(key)

        for response_code in config.response_codes:
            response_definition = SIP_CATALOG.get_response(response_code)
            related_methods = tuple(
                method.value for method in response_definition.related_methods
            ) or ("INVITE",)
            for related_method in related_methods:
                for layer in config.layers:
                    for strategy in config.strategies:
                        if strategy not in _SUPPORTED_STRATEGIES.get(
                            layer, frozenset()
                        ):
                            continue
                        key = (
                            related_method,
                            response_code,
                            related_method,
                            layer,
                            strategy,
                        )
                        if key not in seen:
                            seen.add(key)
                            combos.append(key)

        for case_id, (
            method,
            response_code,
            related_method,
            layer,
            strategy,
        ) in enumerate(combos):
            if case_id >= config.max_cases:
                break
            if case_id <= skip_before:
                continue
            yield CaseSpec(
                case_id=case_id,
                seed=config.seed_start + case_id,
                method=method,
                layer=layer,
                strategy=strategy,
                response_code=response_code,
                related_method=related_method,
            )


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
    ) -> None:
        # Resume: restore original config from JSONL before initializing anything else.
        # Only output_path and resume flag are kept from the new invocation.
        if config.resume and store is None:
            _tmp_store = ResultStore(Path(config.output_path))
            _checkpoint = _tmp_store.find_checkpoint()
            if _checkpoint is not None:
                _, _, _, _, _original_config = _checkpoint
                config = _original_config.model_copy(
                    update={"resume": True, "output_path": config.output_path}
                )
        self._config = config
        self._generator = generator or SIPGenerator(GeneratorSettings())
        self._mutator = mutator or SIPMutator()
        self._sender = sender or SIPSenderReactor()
        self._adb_collector: object = None
        _docker_mode = config.mode == "real-ue-direct"
        if oracle is not None:
            self._oracle = oracle
        elif config.adb_enabled:
            from volte_mutation_fuzzer.adb.contracts import AdbCollectorConfig
            from volte_mutation_fuzzer.adb.core import (
                AdbAnomalyDetector,
                AdbLogCollector,
            )

            adb_cfg = AdbCollectorConfig(
                serial=config.adb_serial,
                buffers=config.adb_buffers,
            )
            _collector = AdbLogCollector(adb_cfg)
            _detector = AdbAnomalyDetector()
            _adb_oracle = AdbOracle(_collector, _detector)
            self._adb_collector = _collector
            log_oracle = LogOracle() if config.log_path is not None else None
            self._oracle = OracleEngine(
                log_oracle=log_oracle,
                adb_oracle=_adb_oracle,
                docker_mode=_docker_mode,
            )
        elif config.log_path is not None:
            self._oracle = OracleEngine(
                log_oracle=LogOracle(), docker_mode=_docker_mode
            )
        else:
            self._oracle = OracleEngine(docker_mode=_docker_mode)
        self._store = store or ResultStore(Path(config.output_path))
        self._target = TargetEndpoint(
            host=config.target_host,
            port=config.target_port,
            transport=config.transport,
            mode=config.mode,
            timeout_seconds=config.timeout_seconds,
            msisdn=config.target_msisdn,
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
            output_dir=config.crash_analysis_output,
            enabled=config.crash_analysis,
            source_name=config.output_path,
        )

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

        if self._adb_collector is not None:
            self._adb_collector.start()
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

                target_label = spec.method
                if spec.response_code is not None:
                    related_method = spec.related_method or spec.method
                    target_label = f"{spec.response_code}/{related_method}"
                label = (
                    f"[{spec.case_id + 1}/{config.max_cases}] "
                    f"{target_label} {spec.layer}/{spec.strategy} seed={spec.seed}"
                )
                code_str = (
                    f" ({case_result.response_code},"
                    if case_result.response_code
                    else " ("
                )
                print(
                    f"{label} → {case_result.verdict}{code_str} {case_result.elapsed_ms:.0f}ms)",
                    file=sys.stderr,
                )

                if case_result.verdict == "crash":
                    print(
                        f"  [CRASH] reproduction: {case_result.reproduction_cmd}",
                        file=sys.stderr,
                    )
                if case_result.verdict == "stack_failure":
                    print(
                        f"  [STACK_FAILURE] {case_result.reason}",
                        file=sys.stderr,
                    )
                    print(
                        f"  [STACK_FAILURE] reproduction: {case_result.reproduction_cmd}",
                        file=sys.stderr,
                    )
                if case_result.verdict == "unknown":
                    print(
                        f"  [ERROR] {case_result.reason}",
                        file=sys.stderr,
                    )
                if case_result.verdict == "infra_failure":
                    print(
                        f"  [INFRA FAILURE] {case_result.reason}",
                        file=sys.stderr,
                    )

                # Warn if ADB collector has lost connection
                if (
                    self._adb_collector is not None
                    and hasattr(self._adb_collector, "is_healthy")
                    and not self._adb_collector.is_healthy
                ):
                    dead = getattr(self._adb_collector, "dead_buffers", frozenset())
                    if dead:
                        print(
                            f"  [ADB WARNING] collector unhealthy — dead buffers: {','.join(sorted(dead))}",
                            file=sys.stderr,
                        )

                # SA expiry → immediate abort
                if sa_checked_dead:
                    print(
                        "[vmf campaign] CIRCUIT BREAKER: IPsec SA expired — "
                        "aborting campaign. Re-register the UE and restart.",
                        file=sys.stderr,
                    )
                    logger.error("circuit breaker tripped: IPsec SA expired")
                    break

                if cb_threshold > 0 and consecutive_failures >= cb_threshold:
                    print(
                        f"[vmf campaign] CIRCUIT BREAKER: {consecutive_failures} consecutive"
                        f" timeout/unknown verdicts — aborting campaign",
                        file=sys.stderr,
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
            return campaign
        finally:
            if self._adb_collector is not None:
                self._adb_collector.stop()

            # Generate final crash analysis report
            self._finalize_crash_analysis()

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
        return campaign

    def _execute_case(self, spec: CaseSpec) -> CaseResult:
        config = self._config
        timestamp = time.time()
        error: str | None = None
        capture: PcapCapture | None = None
        pcap_path_saved: str | None = None

        try:
            # MT INVITE template path (real-ue-direct with replay template)
            if (
                self._mt_template_text is not None
                and spec.response_code is None
                and spec.method == "INVITE"
            ):
                return self._execute_mt_template_case(spec, timestamp)

            # If this method requires a dialog, use DialogOrchestrator
            if spec.response_code is None:
                scenario = scenario_for_method(spec.method)
                if scenario is not None:
                    return self._execute_dialog_case(spec, scenario, timestamp)

            packet = self._build_packet(spec)
            mutated: MutatedCase = self._mutator.mutate(
                packet,
                MutationConfig(
                    seed=spec.seed,
                    strategy=spec.strategy,
                    layer=spec.layer,
                ),
            )
            artifact = self._artifact_from_mutated(mutated)
            if config.pcap_enabled:
                pcap_dir = Path(config.pcap_dir)
                pcap_dir.mkdir(parents=True, exist_ok=True)
                pcap_path = str(pcap_dir / f"case_{spec.case_id:06d}.pcap")
                capture = PcapCapture(pcap_path, interface=config.pcap_interface)
                capture.start()
            try:
                send_result = self._sender.send_artifact(
                    artifact, self._target, collect_all_responses=True
                )
            finally:
                if capture is not None:
                    pcap_path_saved = capture.stop()

            context = OracleContext(
                method=spec.related_method or spec.method,
                timeout_threshold_ms=config.timeout_seconds * 1000,
            )
            process_name = config.process_name if config.check_process else None
            verdict = self._oracle.evaluate(
                send_result,
                context,
                process_name=process_name,
                log_path=config.log_path,
                process_check_interval=10,
            )
            if verdict.verdict in ("crash", "stack_failure") and config.adb_enabled:
                try:
                    from volte_mutation_fuzzer.adb.core import AdbConnector

                    output_dir = str(
                        Path(config.output_path).parent
                        / "adb_snapshots"
                        / f"case_{spec.case_id}"
                    )
                    AdbConnector(serial=config.adb_serial).take_snapshot(output_dir)
                except Exception as exc:
                    logger.warning(
                        "failed to capture adb snapshot for case %s: %s",
                        spec.case_id,
                        exc,
                    )

            mutation_ops = tuple(
                f"{r.operator}({r.target.path})" for r in mutated.records
            )
            raw_response: str | None = None
            if (
                verdict.verdict in ("suspicious", "crash", "stack_failure")
                and send_result.final_response
            ):
                raw_response = send_result.final_response.raw_text or None

            return CaseResult(
                case_id=spec.case_id,
                seed=spec.seed,
                method=spec.method,
                layer=spec.layer,
                strategy=spec.strategy,
                mutation_ops=mutation_ops,
                verdict=verdict.verdict,
                reason=verdict.reason,
                response_code=verdict.response_code,
                elapsed_ms=verdict.elapsed_ms,
                process_alive=verdict.process_alive,
                raw_response=raw_response,
                reproduction_cmd=self._build_reproduction_cmd(spec),
                error=error,
                timestamp=timestamp,
                fuzz_response_code=spec.response_code,
                fuzz_related_method=spec.related_method,
                pcap_path=pcap_path_saved,
            )

        except Exception as exc:
            error = str(exc)
            return CaseResult(
                case_id=spec.case_id,
                seed=spec.seed,
                method=spec.method,
                layer=spec.layer,
                strategy=spec.strategy,
                verdict="unknown",
                reason=f"executor error: {error}",
                elapsed_ms=0.0,
                reproduction_cmd=self._build_reproduction_cmd(spec),
                error=error,
                timestamp=timestamp,
                fuzz_response_code=spec.response_code,
                fuzz_related_method=spec.related_method,
                pcap_path=pcap_path_saved,
            )

    def _resolve_ports_cached(self, msisdn: str) -> tuple[int, int]:
        """Return cached (port_pc, port_ps) or resolve and cache them."""
        if self._cached_ports is not None:
            return self._cached_ports
        ports = self._ue_resolver.resolve_protected_ports(msisdn)
        self._cached_ports = ports
        return ports

    def _execute_mt_template_case(self, spec: CaseSpec, timestamp: float) -> CaseResult:
        """Execute one MT INVOKE replay-template case against a real UE."""
        config = self._config
        assert self._mt_template_text is not None
        assert config.target_msisdn is not None

        error: str | None = None
        capture: PcapCapture | None = None
        pcap_path_saved: str | None = None

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

            # 3. Build slots
            # mt_local_port는 반드시 Via sent-by와 실제 bind 포트 양쪽에 동일하게
            # 적용돼야 A31이 보낸 100/180 응답을 수신할 수 있다.
            pcscf_ip = os.environ.get("VMF_REAL_UE_PCSCF_IP", _DEFAULT_PCSCF_IP)
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

            # 3. Render template
            wire_text = render_mt_invite(self._mt_template_text, slots)

            # 4. Fragmentation guard (plaintext UDP, host-direct only)
            # bypass 모드(Docker 내부망)는 IP fragmentation이 허용된다.
            # null 모드(호스트 직접)는 실제 LTE 경로로 가므로 fragmentation 제한 필요.
            if (
                self._target.transport.upper() == "UDP"
                and config.ipsec_mode == "null"
                and len(wire_text.encode("utf-8")) > _MT_TEMPLATE_FRAG_LIMIT
            ):
                return CaseResult(
                    case_id=spec.case_id,
                    seed=spec.seed,
                    method=spec.method,
                    layer=spec.layer,
                    strategy=spec.strategy,
                    verdict="unknown",
                    reason=(
                        f"template payload exceeds one-fragment UDP safety threshold "
                        f"({_MT_TEMPLATE_FRAG_LIMIT} bytes)"
                    ),
                    elapsed_ms=0.0,
                    reproduction_cmd=self._build_mt_template_reproduction_cmd(spec),
                    error="fragmentation-guard",
                    timestamp=timestamp,
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
                    strategy=spec.strategy,
                    layer=effective_layer,
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

            # 9. pcap + send
            # 실제 송신은 port_pc로 간다. Plaintext UDP 경로라 ESP 정책 매칭이
            # 아닌 단순 UDP 수신 포트가 port_pc다. bind_port는 슬롯에 주입한
            # Via sent-by와 동일해야 응답 수신 가능하다.

            # ipsec_mode에 따라 송신 방식 결정
            target_update = {
                "host": ue_ip,
                "port": port_pc,
                "bind_port": config.mt_local_port,
            }
            if config.ipsec_mode in ("null", "bypass"):
                # Both modes: send from pcscf container netns
                target_update["source_ip"] = None
                target_update["bind_container"] = "pcscf"

            mt_target = self._target.model_copy(update=target_update)
            if config.pcap_enabled:
                pcap_dir = Path(config.pcap_dir)
                pcap_dir.mkdir(parents=True, exist_ok=True)
                pcap_path = str(pcap_dir / f"case_{spec.case_id:06d}.pcap")
                capture = PcapCapture(pcap_path, interface=config.pcap_interface)
                capture.start()
            try:
                send_result = self._sender.send_artifact(
                    artifact, mt_target, collect_all_responses=True
                )
            finally:
                if capture is not None:
                    pcap_path_saved = capture.stop()

            # 9b. Send CANCEL to tear down the INVITE session
            try:
                cancel_text = wire_text.replace(
                    "INVITE sip:", "CANCEL sip:"
                ).replace(
                    "CSeq: 1 INVITE", "CSeq: 1 CANCEL"
                )
                cancel_artifact = SendArtifact(
                    wire_text=cancel_text,
                    preserve_via=config.preserve_via,
                    preserve_contact=config.preserve_contact,
                )
                self._sender.send_artifact(
                    cancel_artifact, mt_target, collect_all_responses=False
                )
            except Exception:
                pass  # best-effort CANCEL

            # 10. Oracle
            context = OracleContext(
                method=spec.method,
                timeout_threshold_ms=config.timeout_seconds * 1000,
            )
            process_name = config.process_name if config.check_process else None
            verdict = self._oracle.evaluate(
                send_result,
                context,
                process_name=process_name,
                log_path=config.log_path,
                process_check_interval=10,
            )

            # 11. ADB snapshot on crash/stack_failure
            if verdict.verdict in ("crash", "stack_failure") and config.adb_enabled:
                try:
                    from volte_mutation_fuzzer.adb.core import AdbConnector

                    output_dir = str(
                        Path(config.output_path).parent
                        / "adb_snapshots"
                        / f"case_{spec.case_id}"
                    )
                    AdbConnector(serial=config.adb_serial).take_snapshot(output_dir)
                except Exception as exc:
                    logger.warning(
                        "failed to capture adb snapshot for case %s: %s",
                        spec.case_id,
                        exc,
                    )

            mutation_ops = tuple(
                f"{r.operator}({r.target.path})" for r in mutated_wire.records
            )
            raw_response: str | None = None
            if (
                verdict.verdict in ("suspicious", "crash", "stack_failure")
                and send_result.final_response
            ):
                raw_response = send_result.final_response.raw_text or None

            return CaseResult(
                case_id=spec.case_id,
                seed=spec.seed,
                method=spec.method,
                layer=spec.layer,
                strategy=spec.strategy,
                mutation_ops=mutation_ops,
                verdict=verdict.verdict,
                reason=verdict.reason,
                response_code=verdict.response_code,
                elapsed_ms=verdict.elapsed_ms,
                process_alive=verdict.process_alive,
                raw_response=raw_response,
                reproduction_cmd=self._build_mt_template_reproduction_cmd(spec),
                error=error,
                timestamp=timestamp,
                fuzz_response_code=spec.response_code,
                fuzz_related_method=spec.related_method,
                pcap_path=pcap_path_saved,
            )

        except Exception as exc:
            error = str(exc)
            return CaseResult(
                case_id=spec.case_id,
                seed=spec.seed,
                method=spec.method,
                layer=spec.layer,
                strategy=spec.strategy,
                verdict="unknown",
                reason=f"mt-template executor error: {error}",
                elapsed_ms=0.0,
                reproduction_cmd=self._build_mt_template_reproduction_cmd(spec),
                error=error,
                timestamp=timestamp,
                fuzz_response_code=spec.response_code,
                fuzz_related_method=spec.related_method,
                pcap_path=pcap_path_saved,
            )

    def _build_mt_template_reproduction_cmd(self, spec: CaseSpec) -> str:
        cfg = self._config
        return (
            f"uv run fuzzer campaign run"
            f" --mode real-ue-direct"
            f" --target-host {cfg.target_host}"
            f" --target-msisdn {cfg.target_msisdn}"
            f" --impi {cfg.impi}"
            f" --mt-invite-template {cfg.mt_invite_template}"
            f" --ipsec-mode {cfg.ipsec_mode}"
            f"{' --preserve-via' if cfg.preserve_via else ''}"
            f"{' --preserve-contact' if cfg.preserve_contact else ''}"
            f" --mt-local-port {cfg.mt_local_port}"
            f" --methods INVITE"
            f" --layer {spec.layer}"
            f" --strategy {spec.strategy}"
            f" --seed-start {spec.seed}"
            f" --max-cases 1"
            # note: port_pc/port_ps are re-queried live; may differ if UE re-registered
        )

    def _execute_dialog_case(
        self, spec: CaseSpec, scenario, timestamp: float
    ) -> CaseResult:
        orchestrator = DialogOrchestrator(self._generator, self._mutator, self._target)
        mutation_config = MutationConfig(
            seed=spec.seed,
            strategy=spec.strategy,
            layer=spec.layer,
        )
        config = self._config
        capture: PcapCapture | None = None
        pcap_path_saved: str | None = None
        try:
            if config.pcap_enabled:
                pcap_dir = Path(config.pcap_dir)
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
            return CaseResult(
                case_id=spec.case_id,
                seed=spec.seed,
                method=spec.method,
                layer=spec.layer,
                strategy=spec.strategy,
                verdict="unknown",
                reason=f"dialog executor error: {exc}",
                elapsed_ms=0.0,
                reproduction_cmd=self._build_reproduction_cmd(spec),
                error=str(exc),
                timestamp=timestamp,
                pcap_path=pcap_path_saved,
            )

        if not exchange.setup_succeeded:
            return CaseResult(
                case_id=spec.case_id,
                seed=spec.seed,
                method=spec.method,
                layer=spec.layer,
                strategy=spec.strategy,
                verdict="unknown",
                reason=f"dialog setup failed: {exchange.error or 'unknown'}",
                elapsed_ms=0.0,
                reproduction_cmd=self._build_reproduction_cmd(spec),
                error=exchange.error,
                timestamp=timestamp,
                pcap_path=pcap_path_saved,
            )

        fuzz_result = exchange.fuzz_result
        send_result = fuzz_result.send_result if fuzz_result is not None else None

        if send_result is None:
            return CaseResult(
                case_id=spec.case_id,
                seed=spec.seed,
                method=spec.method,
                layer=spec.layer,
                strategy=spec.strategy,
                verdict="unknown",
                reason="dialog fuzz step produced no send result",
                elapsed_ms=0.0,
                reproduction_cmd=self._build_reproduction_cmd(spec),
                timestamp=timestamp,
                pcap_path=pcap_path_saved,
            )

        context = OracleContext(
            method=spec.method,
            timeout_threshold_ms=config.timeout_seconds * 1000,
        )
        process_name = config.process_name if config.check_process else None
        verdict = self._oracle.evaluate(
            send_result,
            context,
            process_name=process_name,
            log_path=config.log_path,
            process_check_interval=10,
        )

        raw_response: str | None = None
        if (
            verdict.verdict in ("suspicious", "crash", "stack_failure")
            and send_result.final_response
        ):
            raw_response = send_result.final_response.raw_text or None

        return CaseResult(
            case_id=spec.case_id,
            seed=spec.seed,
            method=spec.method,
            layer=spec.layer,
            strategy=spec.strategy,
            mutation_ops=(),
            verdict=verdict.verdict,
            reason=verdict.reason,
            response_code=verdict.response_code,
            elapsed_ms=verdict.elapsed_ms,
            process_alive=verdict.process_alive,
            raw_response=raw_response,
            reproduction_cmd=self._build_reproduction_cmd(spec),
            timestamp=timestamp,
            pcap_path=pcap_path_saved,
        )

    def _build_packet(self, spec: CaseSpec) -> object:
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

    def _build_reproduction_cmd(self, spec: CaseSpec) -> str:
        cfg = self._config
        if spec.response_code is not None:
            context = json.dumps(
                self._synthetic_dialog_context().model_dump(mode="json"),
                ensure_ascii=False,
            )
            related_method = spec.related_method or spec.method
            return (
                f"uv run fuzzer mutate response {spec.response_code} {related_method}"
                f" --context '{context}'"
                f" --strategy {spec.strategy}"
                f" --layer {spec.layer}"
                f" --seed {spec.seed}"
                f" | uv run fuzzer send packet"
                f" --mode {cfg.mode}"
                f" --target-host {cfg.target_host}"
                f" --target-port {cfg.target_port}"
                f"{f' --source-ip {cfg.source_ip}' if cfg.source_ip else ''}"
                f"{f' --bind-container {cfg.bind_container}' if cfg.bind_container else ''}"
                f"{f' --bind-port {cfg.mt_local_port}' if cfg.mode == 'real-ue-direct' and cfg.mt_invite_template is not None else ''}"
            )
        return (
            f"uv run fuzzer mutate request {spec.method}"
            f" --strategy {spec.strategy}"
            f" --layer {spec.layer}"
            f" --seed {spec.seed}"
            f" | uv run fuzzer send packet"
            f" --mode {cfg.mode}"
            f" --target-host {cfg.target_host}"
            f" --target-port {cfg.target_port}"
            f" --ipsec-mode {cfg.ipsec_mode}"
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
