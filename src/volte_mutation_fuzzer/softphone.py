from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Final

SOFTPHONE_BIN_ENV: Final[str] = "VMF_SOFTPHONE_BIN"
SOFTPHONE_CONFIG_DIR_ENV: Final[str] = "VMF_SOFTPHONE_CONFIG_DIR"
SOFTPHONE_ARGS_ENV: Final[str] = "VMF_SOFTPHONE_ARGS"
_DEFAULT_BARESIP_BINARY: Final[str] = "baresip"


class SoftphoneConfigError(ValueError):
    """Raised when the local softphone execution environment is incomplete."""


def _read_env(env: Mapping[str, str], key: str) -> str | None:
    value = env.get(key)
    if value is None:
        return None

    stripped = value.strip()
    return stripped or None


def _which(binary_name: str, env: Mapping[str, str]) -> str | None:
    return shutil.which(binary_name, path=env.get("PATH"))


def resolve_baresip_binary(env: Mapping[str, str] | None = None) -> str:
    env_map = os.environ if env is None else env
    configured_binary = _read_env(env_map, SOFTPHONE_BIN_ENV)
    if configured_binary is not None:
        discovered_binary = _which(configured_binary, env_map)
        if discovered_binary is not None:
            return discovered_binary
        raise SoftphoneConfigError(
            f"configured softphone binary not found: {configured_binary}"
        )

    discovered_binary = _which(_DEFAULT_BARESIP_BINARY, env_map)
    if discovered_binary is not None:
        return discovered_binary

    raise SoftphoneConfigError(
        "baresip binary not found; set VMF_SOFTPHONE_BIN or install baresip on PATH"
    )


def resolve_baresip_config_dir(env: Mapping[str, str] | None = None) -> Path:
    env_map = os.environ if env is None else env
    configured_dir = _read_env(env_map, SOFTPHONE_CONFIG_DIR_ENV)
    if configured_dir is None:
        raise SoftphoneConfigError(
            "VMF_SOFTPHONE_CONFIG_DIR must point to an existing baresip config directory"
        )

    config_dir = Path(configured_dir).expanduser()
    if not config_dir.is_dir():
        raise SoftphoneConfigError(
            f"baresip config directory does not exist: {config_dir}"
        )

    return config_dir


def parse_baresip_args(env: Mapping[str, str] | None = None) -> list[str]:
    env_map = os.environ if env is None else env
    configured_args = _read_env(env_map, SOFTPHONE_ARGS_ENV)
    if configured_args is None:
        return []

    return shlex.split(configured_args)


def build_baresip_command(env: Mapping[str, str] | None = None) -> list[str]:
    config_dir = resolve_baresip_config_dir(env)
    binary = resolve_baresip_binary(env)
    return [binary, "-f", str(config_dir), *parse_baresip_args(env)]


def run_baresip(
    env: Mapping[str, str] | None = None,
    *,
    runner: Callable[
        ..., subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]
    ]
    | None = None,
) -> int:
    command = build_baresip_command(env)
    execute = runner or subprocess.run
    completed = execute(command, check=False)
    return int(completed.returncode)


def main(argv: Sequence[str] | None = None) -> None:
    del argv

    try:
        raise SystemExit(run_baresip())
    except SoftphoneConfigError as exc:
        print(f"[vmf softphone] {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    except OSError as exc:
        print(f"[vmf softphone] failed to launch baresip: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    except KeyboardInterrupt as exc:
        raise SystemExit(130) from exc


__all__ = [
    "SOFTPHONE_ARGS_ENV",
    "SOFTPHONE_BIN_ENV",
    "SOFTPHONE_CONFIG_DIR_ENV",
    "SoftphoneConfigError",
    "build_baresip_command",
    "main",
    "parse_baresip_args",
    "resolve_baresip_binary",
    "resolve_baresip_config_dir",
    "run_baresip",
]


if __name__ == "__main__":
    main()
