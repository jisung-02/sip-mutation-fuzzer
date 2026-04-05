import json
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
from volte_mutation_fuzzer.generator.contracts import (
    DialogContext,
    GeneratorSettings,
    RequestSpec,
    ResponseSpec,
)
from volte_mutation_fuzzer.generator.core import SIPGenerator
from volte_mutation_fuzzer.mutator.contracts import MutationConfig, MutatedCase
from volte_mutation_fuzzer.mutator.core import SIPMutator
from volte_mutation_fuzzer.oracle.contracts import OracleContext
from volte_mutation_fuzzer.oracle.core import AdbOracle, LogOracle, OracleEngine
from volte_mutation_fuzzer.sender.contracts import (
    SendArtifact,
    TargetEndpoint,
)
from volte_mutation_fuzzer.sender.core import SIPSenderReactor
from volte_mutation_fuzzer.sip.catalog import SIP_CATALOG
from volte_mutation_fuzzer.sip.common import SIPMethod, SIPURI


# layer별 지원 전략 매핑 — mutator/core.py _validate_supported_strategy와 동기화
_SUPPORTED_STRATEGIES: dict[str, frozenset[str]] = {
    "model": frozenset({"default", "state_breaker"}),
    "wire": frozenset({"default"}),
    "byte": frozenset({"default"}),
}


# ---------------------------------------------------------------------------
# CaseGenerator
# ---------------------------------------------------------------------------


class CaseGenerator:
    """Produces CaseSpec instances from direct method and response selections."""

    def __init__(self, config: CampaignConfig) -> None:
        self._config = config

    def generate(self) -> Iterator[CaseSpec]:
        config = self._config
        seen: set[tuple[str, int | None, str | None, str, str]] = set()
        combos: list[tuple[str, int | None, str | None, str, str]] = []

        for method in config.methods:
            for layer in config.layers:
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
            from volte_mutation_fuzzer.adb.core import AdbAnomalyDetector, AdbLogCollector

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
        )

    def run(self) -> CampaignResult:
        config = self._config
        campaign_id = uuid.uuid4().hex[:12]
        started_at = datetime.now(timezone.utc).isoformat()
        summary = CampaignSummary()

        campaign = CampaignResult(
            campaign_id=campaign_id,
            started_at=started_at,
            status="running",
            config=config,
            summary=summary,
        )
        self._store.write_header(campaign)

        if self._adb_collector is not None:
            self._adb_collector.start()
        try:
            for spec in CaseGenerator(config).generate():
                case_result = self._execute_case(spec)
                self._store.append(case_result)
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

        campaign = campaign.model_copy(
            update={
                "status": "completed",
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

        try:
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
            send_result = self._sender.send_artifact(
                artifact, self._target, collect_all_responses=True
            )

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
                f" --target-host {cfg.target_host}"
                f" --target-port {cfg.target_port}"
            )
        return (
            f"uv run fuzzer mutate request {spec.method}"
            f" --strategy {spec.strategy}"
            f" --layer {spec.layer}"
            f" --seed {spec.seed}"
            f" | uv run fuzzer send packet"
            f" --target-host {cfg.target_host}"
            f" --target-port {cfg.target_port}"
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
            case _:
                summary.unknown += 1
