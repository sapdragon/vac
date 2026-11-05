#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MSBUILD = Path(r"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe")

TESTS = [
    ("modules/payload_executor/tests/parity.vcxproj", "Win32"),
    ("tests/dispatch/dispatch_parity.vcxproj", "Win32"),
    ("tests/sdk/sdk_tests.vcxproj", "Win32"),
    ("tests/service/test_module.vcxproj", "Win32"),
    ("tests/service/test_module_entry.vcxproj", "Win32"),
    ("tests/service/service_tests.vcxproj", "Win32"),
    ("modules/shared_section/tests/parity.vcxproj", "Win32"),
    ("modules/system_handles/tests/parity.vcxproj", "Win32"),
    ("modules/target_handles/tests/parity.vcxproj", "Win32"),
    ("modules/system_info/tests/parity.vcxproj", "Win32"),
    ("modules/process_memory_map/tests/regression.vcxproj", "Win32"),
    ("modules/driver_inventory/tests/regression.vcxproj", "Win32"),
    ("modules/image_scan_threads/tests/thread_fixture.vcxproj", "Win32"),
    ("modules/image_scan_threads/tests/thread_fixture.vcxproj", "x64"),
]


def build(project: str, platform: str) -> bool:
    command = [str(MSBUILD), project, "-p:Configuration=Release", f"-p:Platform={platform}",
               f"-p:SolutionDir={ROOT}\\", "-nologo", "-v:q", "-m"]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, errors="replace")
    errors = [line for line in result.stdout.splitlines() if " error " in line]
    print(f"{'ok  ' if result.returncode == 0 else 'FAIL'} {project} [{platform}]")
    for line in errors[:10]:
        print("    " + line[:220])
    return result.returncode == 0


def main() -> int:
    results = [build("vac.sln", "Win32")]
    results += [build(project, platform) for project, platform in TESTS]
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
