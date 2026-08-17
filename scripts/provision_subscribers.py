#!/usr/bin/env python3
"""
가입자 프로비저닝 스크립트
- Open5GS HSS (MongoDB)
- PyHSS (MySQL) for IMS/VoLTE

사용법: poe provision
"""

import json
import subprocess
import sys
import urllib.request
from pathlib import Path
from urllib.error import HTTPError


def load_env(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        env[key.strip()] = value.strip()
    return env


def check_epc_running() -> bool:
    result = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"],
        capture_output=True,
        text=True,
    )
    running = set(result.stdout.splitlines())
    # 프로비저닝에 필요한 컨테이너 전부: Open5GS HSS(dbctl), mongo(mongosh),
    # PyHSS(HTTP). hss 하나만 검사하면 나머지가 죽어 있을 때 중반에 실패한다.
    missing = {"hss", "mongo", "pyhss"} - running
    if missing:
        print(f"Missing containers: {', '.join(sorted(missing))}")
        return False
    return True


def docker_exec(container: str, *cmd: str) -> tuple[int, str, str]:
    result = subprocess.run(
        ["docker", "exec", container, *cmd],
        capture_output=True,
        text=True,
    )
    return result.returncode, result.stdout, result.stderr


def _json_request(url: str, method: str, data: dict) -> tuple[int, bytes]:
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read()
    except HTTPError as e:
        return e.code, e.read()
    except Exception:
        return 0, b""


def put_json(url: str, data: dict) -> tuple[int, bytes]:
    return _json_request(url, "PUT", data)


def patch_json(url: str, data: dict) -> tuple[int, bytes]:
    return _json_request(url, "PATCH", data)


def get_json(url: str) -> tuple[int, bytes]:
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read()
    except HTTPError as e:
        return e.code, e.read()
    except Exception:
        return 0, b""


def upsert_pyhss(
    base_url: str,
    resource: str,
    data: dict,
    lookup_key: str,
    lookup_val: str,
    update_data: dict | None = None,
) -> tuple[int, dict]:
    """PUT으로 생성 시도, 이미 존재하면 /imsi/ 엔드포인트로 조회 후 PATCH로 업데이트.

    update_data: PATCH 시 사용할 데이터 (None이면 data 사용).
                 sqn 등 리셋하면 안 되는 필드를 제외할 때 활용.
    """
    status, body = put_json(f"{base_url}/{resource}/", data)
    if status in (200, 201):
        try:
            return status, json.loads(body)
        except Exception:
            return status, {}

    # PUT 실패 시 /imsi/ 엔드포인트로 기존 레코드 조회 후 PATCH
    get_status, get_body = get_json(f"{base_url}/{resource}/imsi/{lookup_val}")
    if get_status == 200:
        try:
            record = json.loads(get_body)
            if isinstance(record, dict) and "Result" not in record:
                rid = record.get(f"{resource}_id") or record.get("id")
                if rid:
                    patch_data = update_data if update_data is not None else data
                    patch_status, patch_body = patch_json(
                        f"{base_url}/{resource}/{rid}", patch_data
                    )
                    try:
                        return patch_status, json.loads(patch_body)
                    except Exception:
                        return patch_status, {}
        except Exception:
            pass

    return status, {}


def provision_open5gs(env: dict, subscribers: list[dict]) -> None:
    print("[1/2] Open5GS HSS (MongoDB)")
    print("-" * 40)

    failures: list[str] = []
    for ue in subscribers:
        imsi = ue["imsi"]
        ki = ue["ki"]
        opc = ue["opc"]
        print(f"  Adding IMSI: {imsi}")

        # open5gs-dbctl은 KI/OPC를 바꿔서 넣는 버그가 있으므로 mongosh로 직접 upsert
        mongo_script = f"""
const imsi = "{imsi}";
const ki = "{ki}";
const opc = "{opc}";
const msisdn = "{ue["msisdn"]}";

const defaultSlice = [{{
  sst: 1,
  default_indicator: true,
  session: [
    {{
      name: "internet", type: 3,
      ambr: {{uplink: {{value: 1, unit: 3}}, downlink: {{value: 1, unit: 3}}}},
      qos: {{index: 9, arp: {{priority_level: 8, pre_emption_capability: 1, pre_emption_vulnerability: 1}}}},
      pcc_rule: []
    }},
    {{
      name: "ims", type: 1,
      ambr: {{uplink: {{value: 1, unit: 3}}, downlink: {{value: 1, unit: 3}}}},
      qos: {{index: 5, arp: {{priority_level: 1, pre_emption_capability: 1, pre_emption_vulnerability: 1}}}},
      pcc_rule: []
    }}
  ]
}}];

const existing = db.subscribers.findOne({{imsi}});
if (existing) {{
  // 기존 레코드 — security 필드 교정 + slice 보정
  const slices = Array.isArray(existing.slice) && existing.slice.length > 0
    ? existing.slice
    : defaultSlice;

  if (!Array.isArray(slices[0].session)) slices[0].session = [];

  // 손상된 ue 필드 제거
  slices[0].session = slices[0].session.map(s => {{ if (s && s.ue) delete s.ue; return s; }});

  // IMS APN 없으면 추가
  if (!slices[0].session.some(s => s && s.name === "ims")) {{
    slices[0].session.push({{
      name: "ims", type: 1,
      ambr: {{uplink: {{value: 1, unit: 3}}, downlink: {{value: 1, unit: 3}}}},
      qos: {{index: 5, arp: {{priority_level: 1, pre_emption_capability: 1, pre_emption_vulnerability: 1}}}},
      pcc_rule: []
    }});
  }}

  // security.sqn은 리셋하지 않음 — 리셋 시 LTE AKA 인증 실패
  db.subscribers.updateOne({{imsi}}, {{$set: {{
    "security.k": ki,
    "security.opc": opc,
    "security.amf": "8000",
    "msisdn": [msisdn],
    "slice": slices
  }}}});
  print("updated");
}} else {{
  // 신규 생성
  db.subscribers.insertOne({{
    imsi: imsi,
    msisdn: [msisdn],
    security: {{k: ki, opc: opc, amf: "8000", sqn: {{low: 0, high: 0, unsigned: false}}}},
    ambr: {{uplink: {{value: 1, unit: 3}}, downlink: {{value: 1, unit: 3}}}},
    slice: defaultSlice,
    access_restriction_data: 32,
    subscriber_status: 0,
    operator_determined_barring: 0,
    network_access_mode: 0,
    subscribed_rau_tau_timer: 12
  }});
  print("inserted");
}}
"""
        rc, out, err = docker_exec(
            "mongo", "mongosh", "open5gs", "--quiet", "--eval", mongo_script
        )
        if rc == 0 and ("inserted" in out or "updated" in out):
            print(f"    {out.strip()}")
        else:
            # The mongosh result used to be discarded entirely: a failed
            # run still printed "Done" and provisioning continued to PyHSS
            # with a half-provisioned Open5GS and a false success report.
            detail = err.strip() or out.strip() or f"mongosh exited with status {rc}"
            print(f"    FAILED: {detail}")
            failures.append(imsi)

    if failures:
        print(f"\n  Open5GS provisioning failed for: {', '.join(failures)}")
        print("  PyHSS provisioning skipped — fix the errors above and re-run")
        sys.exit(1)
    print("  Done\n")


def provision_pyhss(env: dict, subscribers: list[dict]) -> None:
    print("[2/2] PyHSS (IMS)")
    print("-" * 40)

    base_url = env.get("VMF_REAL_UE_PYHSS_URL", "http://localhost:8080")
    failures: list[str] = []

    # APN 생성 (이미 있으면 무시). upsert 결과를 검사한다 — 예전에는
    # 반환 status를 전부 폐기해 PyHSS가 죽어 있어도 성공처럼 진행했다.
    print("  Creating APNs...")
    for apn in ("internet", "ims"):
        status, _ = upsert_pyhss(
            base_url,
            "apn",
            {"apn": apn, "apn_ambr_dl": 0, "apn_ambr_ul": 0},
            "apn",
            apn,
        )
        if not (200 <= status < 300):
            print(f"    FAILED (apn:{apn}): PyHSS returned status {status}")
            failures.append(f"apn:{apn}")
    if not failures:
        print("    APNs ready (internet, ims)")

    mnc = env.get("MNC", "01").zfill(3)
    mcc = env.get("MCC", "001")
    ims_domain = f"ims.mnc{mnc}.mcc{mcc}.3gppnetwork.org"
    scscf_uri = f"sip:scscf.{ims_domain}:6060"

    for ue in subscribers:
        imsi = ue["imsi"]
        ki = ue["ki"]
        opc = ue["opc"]
        msisdn = ue["msisdn"]
        print(f"  Adding IMSI: {imsi} (MSISDN: {msisdn})")

        # AUC 생성 또는 업데이트 (업데이트 시 sqn 리셋 금지 — IMS 인증 깨짐)
        status, auc = upsert_pyhss(
            base_url,
            "auc",
            {"ki": ki, "opc": opc, "amf": "8000", "sqn": 0, "imsi": imsi},
            "imsi",
            imsi,
            update_data={"ki": ki, "opc": opc, "amf": "8000", "imsi": imsi},
        )
        auc_id = auc.get("auc_id") if 200 <= status < 300 else None
        if auc_id is None:
            # upsert 응답에 id가 없으면 자연키 조회로 폴백
            get_status, get_body = get_json(f"{base_url}/auc/imsi/{imsi}")
            if get_status == 200:
                try:
                    record = json.loads(get_body)
                except Exception:
                    record = None
                if isinstance(record, dict) and "Result" not in record:
                    auc_id = record.get("auc_id")
        if auc_id is None:
            # 인덱스 폴백 금지: 기존 auc 행이 있는 테이블에서 루프 인덱스를
            # auc_id로 쓰면 잘못된 참조가 조용히 기록된다.
            print(f"    FAILED ({imsi}): could not resolve auc_id")
            failures.append(imsi)
            continue

        # Subscriber 생성 또는 업데이트
        status, _ = upsert_pyhss(
            base_url,
            "subscriber",
            {
                "imsi": imsi,
                "enabled": True,
                "auc_id": auc_id,
                "default_apn": 1,
                "apn_list": "1,2",
                "msisdn": msisdn,
                "ue_ambr_dl": 0,
                "ue_ambr_ul": 0,
            },
            "imsi",
            imsi,
        )
        if not (200 <= status < 300):
            print(f"    FAILED ({imsi}): subscriber upsert status {status}")
            failures.append(imsi)
            continue

        # IMS Subscriber 생성 또는 업데이트
        # ifc_path 필수 — null이면 S-CSCF MAR에서 403 반환
        scscf_peer = f"scscf.{ims_domain}"
        status, _ = upsert_pyhss(
            base_url,
            "ims_subscriber",
            {
                "imsi": imsi,
                "msisdn": msisdn,
                "sh_profile": "string",
                "scscf_peer": scscf_peer,
                "msisdn_list": f"[{msisdn}]",
                "ifc_path": "default_ifc.xml",
                "scscf": scscf_uri,
                "scscf_realm": ims_domain,
            },
            "imsi",
            imsi,
        )
        if not (200 <= status < 300):
            print(f"    FAILED ({imsi}): ims_subscriber upsert status {status}")
            failures.append(imsi)

    if failures:
        print(f"\n  PyHSS provisioning failed for: {', '.join(failures)}")
        print("  Fix the errors above and re-run")
        sys.exit(1)
    print("  Done\n")


def apply_pyhss_ifc_template(project_root: Path) -> None:
    """Ensure the committed iFC template is active in the pyhss container.

    The template is bind-mounted, so the repo file is the source of truth.
    Restart pyhss so any cached iFC rendering is discarded and the next MAR
    re-renders from disk. Reproducibility contract: after `poe provision`,
    S-CSCF iFC matches `infrastructure/pyhss/default_ifc.xml` exactly.
    """
    repo_ifc = project_root / "infrastructure" / "pyhss" / "default_ifc.xml"
    if not repo_ifc.exists():
        print(f"  Skip: {repo_ifc} missing")
        return

    rc, out, _ = docker_exec("pyhss", "cat", "/mnt/pyhss/default_ifc.xml")
    if rc != 0:
        print("  Skip: pyhss container not running")
        return

    if out != repo_ifc.read_text():
        print(
            "  WARNING: repo iFC differs from pyhss bind mount — check rsync to server"
        )

    print("Restarting pyhss to reload iFC template...")
    subprocess.run(["docker", "restart", "pyhss"], check=False)
    print("  Done — UE must re-REGISTER for new iFC to apply\n")


def main() -> None:
    project_root = Path(__file__).parent.parent
    env_file = project_root / ".env"

    if not env_file.exists():
        print("Error: .env file not found")
        sys.exit(1)

    env = load_env(env_file)

    if not check_epc_running():
        print("Error: EPC is not running")
        print("Run first: poe epc-run")
        sys.exit(1)

    # 가입자 목록 구성
    subscribers = []
    for idx in range(1, 10):
        imsi = env.get(f"UE{idx}_IMSI", "")
        if not imsi:
            break
        subscribers.append(
            {
                "imsi": imsi,
                "ki": env.get(f"UE{idx}_KI", ""),
                "opc": env.get(f"UE{idx}_OPC", ""),
                "msisdn": env.get(f"UE{idx}_MSISDN", ""),
            }
        )

    if not subscribers:
        print("Error: No subscribers defined in .env (UE1_IMSI, UE2_IMSI, ...)")
        sys.exit(1)

    print("=" * 40)
    print("Subscriber Provisioning")
    print("=" * 40)
    print(f"Found {len(subscribers)} subscriber(s) in .env\n")

    provision_open5gs(env, subscribers)
    provision_pyhss(env, subscribers)
    apply_pyhss_ifc_template(project_root)

    print("=" * 40)
    print("Provisioning Complete!")
    print("=" * 40)
    print()
    print("Subscribers:")
    for ue in subscribers:
        print(f"  IMSI: {ue['imsi']}, MSISDN: {ue['msisdn']}")
    print()
    print("Verify:")
    print("  Open5GS WebUI: http://localhost:9999")
    print("  PyHSS API:     http://localhost:8080/docs/")


if __name__ == "__main__":
    main()
