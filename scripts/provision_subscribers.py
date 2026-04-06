#!/usr/bin/env python3
"""
가입자 프로비저닝 스크립트
- Open5GS HSS (MongoDB)
- PyHSS (MySQL) for IMS/VoLTE

사용법: poe provision
"""

import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path


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
    return "hss" in result.stdout.splitlines()


def docker_exec(container: str, *cmd: str) -> tuple[int, str, str]:
    result = subprocess.run(
        ["docker", "exec", container, *cmd],
        capture_output=True,
        text=True,
    )
    return result.returncode, result.stdout, result.stderr


def put_json(url: str, data: dict) -> tuple[int, bytes]:
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method="PUT",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read()
    except Exception:
        return 0, b""


def provision_open5gs(env: dict, subscribers: list[dict]) -> None:
    print("[1/2] Open5GS HSS (MongoDB)")
    print("-" * 40)

    for ue in subscribers:
        imsi = ue["imsi"]
        ki = ue["ki"]
        opc = ue["opc"]
        print(f"  Adding IMSI: {imsi}")

        # open5gs-dbctl로 기본 가입자 추가
        rc, _, _ = docker_exec(
            "hss",
            "/open5gs/misc/db/open5gs-dbctl",
            "add",
            imsi,
            ki,
            opc,
        )
        if rc != 0:
            print("    (already exists or failed, continuing)")

        # IMS APN 추가 (MongoDB에 직접)
        mongo_script = f"""
const imsi = "{imsi}";
const sub = db.subscribers.findOne({{imsi}});
if (sub) {{
  const slices = Array.isArray(sub.slice) ? sub.slice : [{{sst: 1, default_indicator: true, session: []}}];
  if (slices.length === 0) slices.push({{sst: 1, default_indicator: true, session: []}});
  if (!Array.isArray(slices[0].session)) slices[0].session = [];
  const hasIms = slices[0].session.some(s => s && s.name === "ims");
  if (!hasIms) {{
    slices[0].session.push({{
      name: "ims", type: 3,
      ambr: {{uplink: {{value: 1, unit: 3}}, downlink: {{value: 1, unit: 3}}}},
      qos: {{index: 5, arp: {{priority_level: 8, pre_emption_capability: 1, pre_emption_vulnerability: 1}}}},
      pcc_rule: []
    }});
    db.subscribers.updateOne({{imsi}}, {{$set: {{slice: slices}}}});
    print("ims-apn-added");
  }} else {{ print("ims-apn-present"); }}
}} else {{ print("subscriber-not-found"); }}
"""
        docker_exec("mongo", "mongosh", "open5gs", "--quiet", "--eval", mongo_script)

    print("  Done\n")


def provision_pyhss(env: dict, subscribers: list[dict]) -> None:
    print("[2/2] PyHSS (IMS)")
    print("-" * 40)

    base_url = env.get("VMF_REAL_UE_PYHSS_URL", "http://localhost:8080")

    # APN 생성
    print("  Creating APNs...")
    put_json(f"{base_url}/apn/", {"apn": "internet", "apn_ambr_dl": 0, "apn_ambr_ul": 0})
    put_json(f"{base_url}/apn/", {"apn": "ims", "apn_ambr_dl": 0, "apn_ambr_ul": 0})
    print("    APNs created (internet, ims)")

    for i, ue in enumerate(subscribers, start=1):
        imsi = ue["imsi"]
        ki = ue["ki"]
        opc = ue["opc"]
        msisdn = ue["msisdn"]
        print(f"  Adding IMSI: {imsi} (MSISDN: {msisdn})")

        # AUC 생성
        put_json(
            f"{base_url}/auc/",
            {"ki": ki, "opc": opc, "amf": "8000", "sqn": 0, "imsi": imsi},
        )

        # Subscriber 생성
        put_json(
            f"{base_url}/subscriber/",
            {
                "imsi": imsi,
                "enabled": True,
                "auc_id": i,
                "default_apn": 1,
                "apn_list": "1,2",
                "msisdn": msisdn,
                "ue_ambr_dl": 0,
                "ue_ambr_ul": 0,
            },
        )

        # IMS Subscriber 생성
        mnc = env.get("MNC", "01").zfill(3)
        mcc = env.get("MCC", "001")
        ims_domain = f"ims.mnc{mnc}.mcc{mcc}.3gppnetwork.org"
        scscf_uri = f"sip:scscf.{ims_domain}:6060"
        put_json(
            f"{base_url}/ims_subscriber/",
            {
                "imsi": imsi,
                "msisdn": msisdn,
                "msisdn_list": msisdn,
                "scscf": scscf_uri,
            },
        )

    print("  Done\n")


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
