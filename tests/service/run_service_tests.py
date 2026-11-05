#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
WORK = BUILD / "service_test"
SIGN = ROOT / "tools" / "sign_module.py"
TO_SIGN = {
    "test_module.signed.dll": BUILD / "tests" / "test_module.dll",
    "test_module_entry.signed.dll": BUILD / "tests" / "test_module_entry.dll",
    "cpuid.signed.dll": BUILD / "Release" / "Win32" / "cpuid.dll",
    "devices.signed.dll": BUILD / "Release" / "Win32" / "devices.dll",
}


def run(*args) -> None:
    subprocess.run([str(a) for a in args], check=True)


def main() -> int:
    WORK.mkdir(parents=True, exist_ok=True)
    key = WORK / "devkey.json"
    public = WORK / "devkey.hex"
    if not key.exists():
        run(sys.executable, SIGN, "keygen", key, public)
    for name, source in TO_SIGN.items():
        run(sys.executable, SIGN, "sign", key, source, WORK / name)

    service = BUILD / "Release" / "Win32" / "steamservice.exe"
    return subprocess.run([str(BUILD / "tests" / "service_tests.exe"), str(WORK), str(ROOT.parent / "vac-research"), str(service)],
                          cwd=ROOT).returncode


if __name__ == "__main__":
    raise SystemExit(main())
