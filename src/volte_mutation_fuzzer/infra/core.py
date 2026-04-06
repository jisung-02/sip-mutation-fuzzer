import json
import os
import platform
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from ipaddress import ip_network
from pathlib import Path
from typing import Final, Mapping

_DEFAULT_UPF_IP: Final[str] = "172.22.0.8"
_DEFAULT_IMS_SUBNET: Final[str] = "10.20.20.0/24"
_DEFAULT_PCSCF_IP: Final[str] = "172.22.0.21"
_DEFAULT_PYHSS_API: Final[str] = "http://localhost:8080"
_DEFAULT_HSS_CONTAINER: Final[str] = "hss"
_DEFAULT_MONGO_CONTAINER: Final[str] = "mongo"
_DEFAULT_SUBSCRIBER_KEY: Final[str] = "00112233445566778899AABBCCDDEEFF"
_DEFAULT_SUBSCRIBER_OPC: Final[str] = "00112233445566778899AABBCCDDEEFF"
_DEFAULT_SUBSCRIBER_AMF: Final[str] = "8000"
_DEFAULT_START_IMSI: Final[str] = "001010000000001"
_DEFAULT_START_MSISDN: Final[str] = "222222"
_DEFAULT_PAGE_SIZE: Final[int] = 200


@dataclass(frozen=True)
class RouteCommandResult:
    ok: bool
    detail: str


def check_ue_route(ims_subnet: str = _DEFAULT_IMS_SUBNET) -> RouteCommandResult:
    probe_ip = _route_probe_ip(ims_subnet)
    command = ["route", "-n", "get", probe_ip]
    if platform.system() != "Darwin":
        command = ["ip", "route", "get", probe_ip]
    return _run_route_command(command)


def setup_ue_route(
    ims_subnet: str = _DEFAULT_IMS_SUBNET,
    upf_ip: str = _DEFAULT_UPF_IP,
) -> RouteCommandResult:
    commands = [["route", "-n", "add", "-net", ims_subnet, upf_ip]]
    if platform.system() == "Darwin":
        commands.append(["route", "-n", "change", "-net", ims_subnet, upf_ip])
    else:
        commands = [["ip", "route", "replace", ims_subnet, "via", upf_ip]]

    last_failure = f"failed to configure route for {ims_subnet} via {upf_ip}"
    for command in commands:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=10.0,
                check=False,
            )
        except FileNotFoundError as exc:
            return RouteCommandResult(
                False, f"route setup command not found: {exc.filename}"
            )
        except subprocess.TimeoutExpired:
            return RouteCommandResult(False, "route setup command timed out")
        except OSError as exc:
            return RouteCommandResult(False, f"route setup failed: {exc}")

        detail = _first_non_empty_line(result.stdout, result.stderr)
        if result.returncode == 0:
            return RouteCommandResult(
                True,
                detail or f"configured route for {ims_subnet} via {upf_ip}",
            )
        last_failure = detail or f"route setup exited with status {result.returncode}"

    return RouteCommandResult(False, last_failure)


@dataclass(frozen=True)
class UEConfig:
    imsi: str
    key: str
    opc: str
    amf: str
    msisdn: str


class InfraManager:
    def __init__(
        self,
        infra_dir: Path | str | None = None,
        *,
        env: Mapping[str, str] | None = None,
    ) -> None:
        base_env = dict(os.environ if env is None else env)
        self.infra_dir = (
            self._resolve_compose_dir(Path(infra_dir))
            if infra_dir is not None
            else self._find_infra_dir(env=base_env)
        )
        dotenv_path = self.infra_dir / ".env"
        dotenv_vars = _parse_dotenv_file(dotenv_path) if env is None else {}
        self._env = {**dotenv_vars, **base_env}
        self.compose_file = self.infra_dir / "docker-compose.yml"
        self.pyhss_api = (
            _normalize_optional_text(self._env.get("VMF_INFRA_PYHSS_API"))
            or _DEFAULT_PYHSS_API
        )

    @staticmethod
    def _find_infra_dir(
        *,
        env: Mapping[str, str] | None = None,
        start_dir: Path | None = None,
    ) -> Path:
        source = os.environ if env is None else env
        env_dir = _normalize_optional_text(source.get("VMF_INFRA_DIR"))
        if env_dir is not None:
            return InfraManager._resolve_compose_dir(Path(env_dir))

        current = Path(__file__).resolve().parent if start_dir is None else start_dir
        for candidate in (current, *current.parents):
            compose_file = candidate / "docker-compose.yml"
            if compose_file.is_file():
                return candidate

        raise FileNotFoundError(
            "could not locate docker-compose.yml for VMF infrastructure"
        )

    @staticmethod
    def _resolve_compose_dir(path: Path) -> Path:
        expanded = path.expanduser().resolve()
        if expanded.is_file() and expanded.name == "docker-compose.yml":
            return expanded.parent
        if (expanded / "docker-compose.yml").is_file():
            return expanded
        parent = expanded.parent
        if (parent / "docker-compose.yml").is_file():
            return parent
        raise FileNotFoundError(f"docker-compose.yml not found near {expanded}")

    def _run_compose(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["docker", "compose", "-f", str(self.compose_file), *args],
            cwd=self.infra_dir,
            capture_output=True,
            text=True,
            check=False,
        )

    def build(self) -> subprocess.CompletedProcess[str]:
        for command in (
            [
                "docker",
                "build",
                "-t",
                "docker_open5gs",
                str(self.infra_dir / "infrastructure" / "base"),
            ],
            [
                "docker",
                "build",
                "-t",
                "docker_kamailio",
                str(self.infra_dir / "infrastructure" / "ims_base"),
            ],
        ):
            result = subprocess.run(
                command,
                cwd=self.infra_dir,
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                return result
        return self._run_compose("build")

    def up(self, *, detach: bool = True) -> subprocess.CompletedProcess[str]:
        args = ["up"]
        if detach:
            args.append("-d")
        return self._run_compose(*args)

    def down(self) -> subprocess.CompletedProcess[str]:
        return self._run_compose("down")

    def status(self) -> subprocess.CompletedProcess[str]:
        return self._run_compose("ps")

    def is_running(self) -> bool:
        result = self._run_compose("ps", "--status", "running", "--services")
        return result.returncode == 0 and bool(result.stdout.strip())

    def read_ue_configs_from_env(self) -> list[UEConfig]:
        return _read_ue_configs_from_env(self._env)

    def provision_from_env(self) -> list[dict[str, str]]:
        configs = self.read_ue_configs_from_env()
        if not configs:
            raise ValueError(
                "no UE entries found in .env — add UE1_IMSI, UE1_KI, UE1_OPC, UE1_AMF, UE1_MSISDN"
            )
        provisioned: list[dict[str, str]] = []
        for cfg in configs:
            self._provision_hss_subscriber(
                imsi=cfg.imsi, key=cfg.key, opc=cfg.opc, amf=cfg.amf
            )
            self._ensure_ims_apn(cfg.imsi)
            self._provision_pyhss_subscriber(imsi=cfg.imsi, msisdn=cfg.msisdn)
            provisioned.append({"imsi": cfg.imsi, "msisdn": cfg.msisdn})
        return provisioned

    def provision_subscribers(
        self,
        count: int = 1,
        *,
        start_imsi: str = _DEFAULT_START_IMSI,
        start_msisdn: str = _DEFAULT_START_MSISDN,
        key: str = _DEFAULT_SUBSCRIBER_KEY,
        opc: str = _DEFAULT_SUBSCRIBER_OPC,
        amf: str = _DEFAULT_SUBSCRIBER_AMF,
    ) -> list[dict[str, str]]:
        if count < 1:
            raise ValueError("count must be at least 1")

        provisioned: list[dict[str, str]] = []
        for index in range(count):
            imsi = _increment_identifier(start_imsi, index)
            msisdn = _increment_identifier(start_msisdn, index)
            self._provision_hss_subscriber(imsi=imsi, key=key, opc=opc, amf=amf)
            self._ensure_ims_apn(imsi)
            self._provision_pyhss_subscriber(imsi=imsi, msisdn=msisdn)
            provisioned.append({"imsi": imsi, "msisdn": msisdn})
        return provisioned

    def _provision_hss_subscriber(
        self,
        *,
        imsi: str,
        key: str,
        opc: str,
        amf: str,
    ) -> None:
        last_detail = "open5gs-dbctl add failed"
        for command in (
            [
                "docker",
                "exec",
                _DEFAULT_HSS_CONTAINER,
                "/open5gs/misc/db/open5gs-dbctl",
                "add",
                imsi,
                key,
                opc,
                amf,
            ],
            [
                "docker",
                "exec",
                _DEFAULT_HSS_CONTAINER,
                "/open5gs/misc/db/open5gs-dbctl",
                "add",
                imsi,
                key,
                opc,
            ],
        ):
            result = subprocess.run(
                command,
                cwd=self.infra_dir,
                capture_output=True,
                text=True,
                check=False,
            )
            detail = _join_output(result.stdout, result.stderr)
            if result.returncode == 0:
                return
            if "already exists" in detail.casefold() or "duplicate key" in detail.casefold():
                return
            last_detail = detail or f"command exited with status {result.returncode}"
        raise RuntimeError(f"failed to provision HSS subscriber {imsi}: {last_detail}")

    def _ensure_ims_apn(self, imsi: str) -> None:
        script = """
const imsi = %(imsi)s;
const subscriber = db.subscribers.findOne({imsi});
if (!subscriber) {
  print("subscriber-not-found");
  quit(1);
}
const slices = Array.isArray(subscriber.slice) ? subscriber.slice : [];
if (slices.length === 0) {
  slices.push({sst: 1, default_indicator: true, session: []});
}
let imsPresent = false;
for (const item of slices) {
  if (!Array.isArray(item.session)) {
    item.session = [];
  }
  for (const session of item.session) {
    if (session && session.name === "ims") {
      imsPresent = true;
    }
  }
}
if (!imsPresent) {
  slices[0].sst = slices[0].sst ?? 1;
  slices[0].default_indicator = true;
  slices[0].session.push({
    name: "ims",
    type: 3,
    ambr: {
      uplink: {value: 1, unit: 3},
      downlink: {value: 1, unit: 3},
    },
    qos: {
      index: 5,
      arp: {
        priority_level: 8,
        pre_emption_capability: 1,
        pre_emption_vulnerability: 1,
      },
    },
    pcc_rule: [],
  });
  db.subscribers.updateOne({imsi}, {$set: {slice: slices}});
  print("ims-apn-added");
} else {
  print("ims-apn-present");
}
""" % {"imsi": json.dumps(imsi)}
        last_detail = "mongo APN update failed"
        for shell in ("mongosh", "mongo"):
            result = subprocess.run(
                [
                    "docker",
                    "exec",
                    _DEFAULT_MONGO_CONTAINER,
                    shell,
                    "--quiet",
                    "open5gs",
                    "--eval",
                    script,
                ],
                cwd=self.infra_dir,
                capture_output=True,
                text=True,
                check=False,
            )
            detail = _join_output(result.stdout, result.stderr)
            if result.returncode == 0:
                return
            last_detail = detail or f"{shell} exited with status {result.returncode}"
        raise RuntimeError(f"failed to update IMS APN for {imsi}: {last_detail}")

    def _provision_pyhss_subscriber(self, *, imsi: str, msisdn: str) -> None:
        existing = self._list_pyhss_subscribers()
        if any(
            entry.get("imsi") == imsi or entry.get("msisdn") == msisdn
            for entry in existing
            if isinstance(entry, dict)
        ):
            return

        ims_domain = _build_ims_domain(
            self._env.get("MCC", "001"),
            self._env.get("MNC", "01"),
        )
        scscf_uri = f"sip:scscf.{ims_domain}:6060"
        last_error = "PyHSS provisioning failed"
        for endpoint in ("/ims_subscriber/", "/ims_subscriber"):
            for payload in (
                {
                    "imsi": imsi,
                    "msisdn": msisdn,
                    "msisdn_list": msisdn,
                    "scscf": scscf_uri,
                },
                {
                    "imsi": imsi,
                    "msisdn": msisdn,
                    "msisdn_list": [msisdn],
                    "scscf": scscf_uri,
                },
            ):
                request = urllib.request.Request(
                    f"{self.pyhss_api.rstrip('/')}{endpoint}",
                    data=json.dumps(payload).encode("utf-8"),
                    headers={
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        "Provisioning-Key": "hss",
                    },
                    method="PUT",
                )
                try:
                    with urllib.request.urlopen(request, timeout=10.0):
                        return
                except urllib.error.HTTPError as exc:
                    last_error = exc.read().decode("utf-8", errors="replace") or str(
                        exc
                    )
                except urllib.error.URLError as exc:
                    last_error = str(exc)
        raise RuntimeError(
            f"failed to provision PyHSS IMS subscriber {imsi}: {last_error}"
        )

    def _list_pyhss_subscribers(self) -> list[dict[str, object]]:
        request = urllib.request.Request(
            (
                f"{self.pyhss_api.rstrip('/')}/ims_subscriber/list"
                f"?page=0&page_size={_DEFAULT_PAGE_SIZE}"
            ),
            headers={
                "Accept": "application/json",
                "Provisioning-Key": "hss",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=10.0) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, ValueError):
            return []
        if not isinstance(payload, list):
            return []
        return [item for item in payload if isinstance(item, dict)]


def _run_route_command(command: list[str]) -> RouteCommandResult:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
    except FileNotFoundError as exc:
        return RouteCommandResult(
            False, f"route-check command not found: {exc.filename}"
        )
    except subprocess.TimeoutExpired:
        return RouteCommandResult(False, "route-check command timed out")
    except OSError as exc:
        return RouteCommandResult(False, f"route-check failed: {exc}")

    detail = _first_non_empty_line(result.stdout, result.stderr)
    if result.returncode != 0:
        return RouteCommandResult(
            False,
            detail or f"route lookup exited with status {result.returncode}",
        )
    return RouteCommandResult(True, detail or "route is available")


def _route_probe_ip(ims_subnet: str) -> str:
    network = ip_network(ims_subnet, strict=False)
    if network.num_addresses == 1:
        return str(network.network_address)
    return str(network.network_address + 1)


def _increment_identifier(value: str, offset: int) -> str:
    width = len(value)
    return f"{int(value) + offset:0{width}d}"


def _build_ims_domain(raw_mcc: str | None, raw_mnc: str | None) -> str:
    mcc = (raw_mcc or "001").strip()
    mnc = (raw_mnc or "01").strip()
    normalized_mnc = mnc if len(mnc) == 3 else mnc.zfill(3)
    return f"ims.mnc{normalized_mnc}.mcc{mcc}.3gppnetwork.org"


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _first_non_empty_line(*parts: str) -> str:
    for part in parts:
        for line in part.splitlines():
            stripped = line.strip()
            if stripped:
                return stripped
    return ""


def _join_output(*parts: str) -> str:
    return "\n".join(part.strip() for part in parts if part.strip())


def _parse_dotenv_file(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return result
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            continue
        key, _, raw_value = stripped.partition("=")
        key = key.strip()
        value = raw_value.strip().strip("\"'")
        if key:
            result[key] = value
    return result


def _read_ue_configs_from_env(env: Mapping[str, str]) -> list[UEConfig]:
    configs: list[UEConfig] = []
    for i in range(1, 100):
        imsi = env.get(f"UE{i}_IMSI", "").strip()
        if not imsi:
            break
        configs.append(
            UEConfig(
                imsi=imsi,
                key=env.get(f"UE{i}_KI", _DEFAULT_SUBSCRIBER_KEY).strip(),
                opc=env.get(f"UE{i}_OPC", _DEFAULT_SUBSCRIBER_OPC).strip(),
                amf=env.get(f"UE{i}_AMF", _DEFAULT_SUBSCRIBER_AMF).strip(),
                msisdn=env.get(f"UE{i}_MSISDN", "").strip(),
            )
        )
    return configs


__all__ = [
    "InfraManager",
    "RouteCommandResult",
    "UEConfig",
    "check_ue_route",
    "setup_ue_route",
]
