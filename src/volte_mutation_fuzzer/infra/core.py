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
_DEFAULT_PYHSS_IFC_PATH: Final[str] = "default_ifc.xml"


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
        self._ensure_pyhss_apns()
        provisioned: list[dict[str, str]] = []
        for cfg in configs:
            self._provision_hss_subscriber(
                imsi=cfg.imsi, key=cfg.key, opc=cfg.opc, amf=cfg.amf
            )
            self._ensure_ims_apn(cfg.imsi)
            self._provision_pyhss_subscriber(
                imsi=cfg.imsi,
                msisdn=cfg.msisdn,
                key=cfg.key,
                opc=cfg.opc,
                amf=cfg.amf,
            )
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

        self._ensure_pyhss_apns()
        provisioned: list[dict[str, str]] = []
        for index in range(count):
            imsi = _increment_identifier(start_imsi, index)
            msisdn = _increment_identifier(start_msisdn, index)
            self._provision_hss_subscriber(imsi=imsi, key=key, opc=opc, amf=amf)
            self._ensure_ims_apn(imsi)
            self._provision_pyhss_subscriber(
                imsi=imsi, msisdn=msisdn, key=key, opc=opc, amf=amf
            )
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
            if (
                "already exists" in detail.casefold()
                or "duplicate key" in detail.casefold()
            ):
                # open5gs-dbctl cannot update credentials of an existing
                # subscriber: returning here as success left stale K/OPC/AMF
                # in the database, so re-provisioning with rotated keys kept
                # failing AKA authentication. Patch the security fields via
                # the mongo shell instead (same approach as
                # scripts/provision_subscribers.py).
                error = self._update_hss_subscriber_credentials(
                    imsi=imsi, key=key, opc=opc, amf=amf
                )
                if error is not None:
                    raise RuntimeError(
                        "failed to update HSS subscriber credentials for "
                        f"existing subscriber {imsi}: {error}"
                    )
                return
            last_detail = detail or f"command exited with status {result.returncode}"
        raise RuntimeError(f"failed to provision HSS subscriber {imsi}: {last_detail}")

    def _update_hss_subscriber_credentials(
        self,
        *,
        imsi: str,
        key: str,
        opc: str,
        amf: str,
    ) -> str | None:
        """Refresh stored K/OPC/AMF of an existing subscriber; None on success.

        security.sqn is deliberately not written: it tracks the AKA
        sequence number shared with the UE, and resetting it desynchronizes
        the pair and breaks LTE authentication.
        """
        script = """
const imsi = %(imsi)s;
const result = db.subscribers.updateOne(
  {imsi: imsi},
  {$set: {"security.k": %(key)s, "security.opc": %(opc)s, "security.amf": %(amf)s}},
);
if (result.matchedCount === 0) {
  print("subscriber-not-found");
  quit(1);
}
print("credentials-updated");
""" % {
            "imsi": json.dumps(imsi),
            "key": json.dumps(key),
            "opc": json.dumps(opc),
            "amf": json.dumps(amf),
        }
        return self._run_mongo_script(script)

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
  // Session values must match scripts/provision_subscribers.py (type 1 =
  // IPv4, IMS signalling ARP priority 1): the script's values are the
  // ones validated against the real UE, and diverging here silently
  // rewrote subscriber data depending on which provisioner ran last.
  slices[0].session.push({
    name: "ims",
    type: 1,
    ambr: {
      uplink: {value: 1, unit: 3},
      downlink: {value: 1, unit: 3},
    },
    qos: {
      index: 5,
      arp: {
        priority_level: 1,
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
        error = self._run_mongo_script(script)
        if error is not None:
            raise RuntimeError(f"failed to update IMS APN for {imsi}: {error}")

    def _run_mongo_script(self, script: str) -> str | None:
        """Run a JS script against the Open5GS DB; return error detail or None."""
        last_detail = "mongo script failed"
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
            if result.returncode == 0:
                return None
            detail = _join_output(result.stdout, result.stderr)
            last_detail = detail or f"{shell} exited with status {result.returncode}"
        return last_detail

    def _provision_pyhss_subscriber(
        self,
        *,
        imsi: str,
        msisdn: str,
        key: str,
        opc: str,
        amf: str,
    ) -> None:
        """Create or refresh the PyHSS rows a working IMS subscription needs.

        Mirrors scripts/provision_subscribers.py: the previous version only
        PUT a bare ims_subscriber row — without ifc_path the S-CSCF answers
        the MAR with 403 (REGISTER never completes), and without auc/
        subscriber rows IMS AKA authentication data and the EPC-side
        subscriber linkage were missing entirely.
        """
        ims_domain = _build_ims_domain(
            self._env.get("MCC", "001"),
            self._env.get("MNC", "01"),
        )

        auc = self._pyhss_upsert(
            resource="auc",
            data={"ki": key, "opc": opc, "amf": amf, "sqn": 0, "imsi": imsi},
            # The update payload must not carry sqn: it tracks the IMS AKA
            # sequence number shared with the UE, and resetting it breaks
            # authentication (same rule as the provisioning script).
            update_data={"ki": key, "opc": opc, "amf": amf, "imsi": imsi},
            lookup_path=f"imsi/{imsi}",
        )
        auc_id = auc.get("auc_id")
        if auc_id is None:
            status, body = self._pyhss_request(f"/auc/imsi/{imsi}", method="GET")
            record = self._decode_json(body) if status == 200 else {}
            auc_id = record.get("auc_id")
        if auc_id is None:
            raise RuntimeError(
                f"failed to resolve PyHSS auc_id for {imsi}: "
                "auc upsert succeeded but the record exposes no id"
            )

        self._pyhss_upsert(
            resource="subscriber",
            data={
                "imsi": imsi,
                "enabled": True,
                "auc_id": auc_id,
                "default_apn": 1,
                "apn_list": "1,2",
                "msisdn": msisdn,
                "ue_ambr_dl": 0,
                "ue_ambr_ul": 0,
            },
            lookup_path=f"imsi/{imsi}",
        )

        self._pyhss_upsert(
            resource="ims_subscriber",
            data={
                "imsi": imsi,
                "msisdn": msisdn,
                "sh_profile": "string",
                "scscf_peer": f"scscf.{ims_domain}",
                "msisdn_list": f"[{msisdn}]",
                "ifc_path": _DEFAULT_PYHSS_IFC_PATH,
                "scscf": f"sip:scscf.{ims_domain}:6060",
                "scscf_realm": ims_domain,
            },
            lookup_path=f"imsi/{imsi}",
        )

    def _ensure_pyhss_apns(self) -> None:
        for apn in ("internet", "ims"):
            self._pyhss_upsert(
                resource="apn",
                data={"apn": apn, "apn_ambr_dl": 0, "apn_ambr_ul": 0},
                lookup_path=f"apn/{apn}",
            )

    def _pyhss_upsert(
        self,
        *,
        resource: str,
        data: dict[str, object],
        lookup_path: str,
        update_data: dict[str, object] | None = None,
    ) -> dict[str, object]:
        """PUT a PyHSS resource, or PATCH the existing record on conflict.

        Returns the decoded record of the winning request. lookup_path is
        the path segment that addresses the existing record by natural key
        (e.g. "imsi/<imsi>", "apn/<apn>"); the record id it yields is used
        for the PATCH.
        """
        status, body = self._pyhss_request(f"/{resource}/", method="PUT", payload=data)
        if 200 <= status < 300:
            return self._decode_json(body)
        detail = f"PUT /{resource}/ failed with status {status}: {body.strip()}"

        lookup_status, lookup_body = self._pyhss_request(
            f"/{resource}/{lookup_path}", method="GET"
        )
        if lookup_status == 200:
            record = self._decode_json(lookup_body)
            record_id = record.get(f"{resource}_id") or record.get("id")
            if record_id is not None:
                payload = update_data if update_data is not None else data
                patch_status, patch_body = self._pyhss_request(
                    f"/{resource}/{record_id}", method="PATCH", payload=payload
                )
                if 200 <= patch_status < 300:
                    return self._decode_json(patch_body)
                raise RuntimeError(
                    f"failed to update PyHSS {resource}: PATCH /{resource}/"
                    f"{record_id} failed with status {patch_status}: "
                    f"{patch_body.strip()}"
                )
            detail = f"existing {resource} record exposes no id: {lookup_body.strip()}"
        raise RuntimeError(f"failed to provision PyHSS {resource}: {detail}")

    def _pyhss_request(
        self,
        path: str,
        *,
        method: str,
        payload: dict[str, object] | None = None,
    ) -> tuple[int, str]:
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(
            f"{self.pyhss_api.rstrip('/')}{path}",
            data=data,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Provisioning-Key": "hss",
            },
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=10.0) as response:
                return response.status, response.read().decode(
                    "utf-8", errors="replace"
                )
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", errors="replace")
        except urllib.error.URLError as exc:
            return 0, str(exc)

    @staticmethod
    def _decode_json(body: str) -> dict[str, object]:
        try:
            decoded = json.loads(body)
        except ValueError:
            return {}
        return decoded if isinstance(decoded, dict) else {}


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
    if not value.isdigit():
        raise ValueError(f"identifier must be numeric (digits only): {value!r}")
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
