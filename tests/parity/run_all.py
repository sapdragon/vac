#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import compare_vac_worker as cmp

RESEARCH = ROOT.parent / "vac-research"
BUILD = ROOT / "build" / "Release" / "Win32"
TESTS = ROOT / "build" / "tests"
BASELINE = Path(__file__).with_name("baseline.json")
PLACEHOLDER_ID = 0xDEADBEEF
NOISE_SAMPLES = 3
WOW64_TARGET = [r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe",
                "-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 60"]

MODULES = [
    ("boot_config", "boot_config", "ptr_0x0A0830C0_crc_2909d63a_GetRegistryInfo_unk", [0x06A79A9E], None),
    ("cpuid", "cpuid", "ptr_0x0D2A9410_crc_f418b1dc_SomeCpuId_info", [0x023429C3], None),
    ("devices", "devices", "ptr_0x00A69D50_crc_40e4df95_GetDeviceInfo", [0x05EC50DC], None),
    ("system_handles", "system_handles", "ptr_0x0A0C21F8_crc_1da8fb5c_HandleList", [0x002F6DC7], None),
    ("shared_section", "shared_section", "ptr_0x0D2A9410_crc_2794a04_ReadInfoFromMapping", [0x0E3481C0], None),
    ("image_scan", "image_scan", "ptr_0x0D047AF0_crc_33211402_GameCryptoVerify", [0x0CDA6778, 0x09D3248C], None),
    ("image_scan_threads", "image_scan_threads", "ptr_0x0D2534F8_crc_74aa703a_ProcessBaseInfo_unk", [0x05A52008], None),
    ("process_file_identity", "process_file_identity", "ptr_0x0D2058E8_crc_a8848995_GetProcessList_plus2scan", [0x0B2D8276], 0x60),
    ("process_memory_map", "process_memory_map", "ptr_0x0D2058E8_crc_8d88e017_ProcessScan_QVM_PEB", [0x06E048F4], 0x60),
    ("driver_inventory", "driver_inventory", "ptr_0x0D0ACF88_crc_2023d8c3", [0x06ACD913, 0x06C2B5BB], None),
    ("service_lookup", "service_lookup", "ptr_0x0D1EDAE0_crc_87f12249_ServiceInfoByNameHash", [0x0FA94991], None),
    ("system_info", "system_info", "ptr_0x0A00C948_crc_a07ed54b_GetSystemInfo", [0x0F8083A0, 0x0C2232C2], 0x60),
    ("timing_check", "timing_check", "ptr_0x0A0930F0_crc_de9615cb_PEB_BeingDebugged", [0x0D8C40E1], None),
]

RESEARCH_DLL = lambda folder: str(RESEARCH / folder / "module.dll")
# target_handles and payload_executor only run as suites: replaying their captured inputs can issue raw syscalls or run code.
SUITES = [
    ("payload_executor", [TESTS / "payload_executor_parity.exe",
                          RESEARCH_DLL("ptr_0x0D047AF0_crc_60e41c53"),
                          BUILD / "payload_executor.dll", ROOT / "analysis/60e41c53/input_plain.bin"]),
    ("shared_section", [TESTS / "shared_section_parity.exe",
                        RESEARCH_DLL("ptr_0x0D2A9410_crc_2794a04_ReadInfoFromMapping")]),
    ("target_handles", [TESTS / "target_handles_parity.exe",
                              RESEARCH_DLL("ptr_0x0D1F5AE0_crc_762110ce_syscaller")]),
    ("target_handles", [TESTS / "target_handles_parity.exe",
                              RESEARCH_DLL("ptr_0x0D1F5AE0_crc_762110ce_syscaller"), "--live"]),
    ("system_handles", [TESTS / "system_handles_parity.exe",
                        RESEARCH_DLL("ptr_0x0A0C21F8_crc_1da8fb5c_HandleList")]),
    ("system_info", [TESTS / "system_info_parity.exe",
                     RESEARCH_DLL("ptr_0x0A00C948_crc_a07ed54b_GetSystemInfo"),
                     BUILD / "system_info.dll", ROOT / "build/system_info_input.bin"]),
    ("process_memory_map", [TESTS / "process_memory_map_regression.exe"]),
    ("driver_inventory", [TESTS / "driver_inventory_regression.exe"]),
    ("process_file_identity", [sys.executable, ROOT / "tools/test_process_file_identity.py"]),
    ("image_scan_threads", [sys.executable, ROOT / "tools/test_image_scan_threads.py"]),
    ("image_scan", [sys.executable, ROOT / "tools/test_image_scan_edges.py"]),
    ("sdk", [TESTS / "sdk_tests.exe"]),
    ("service", [sys.executable, ROOT / "tests/service/run_service_tests.py"]),
]


def find_node(pe, module_id: int):
    for candidate in (module_id, PLACEHOLDER_ID):
        if pe.scan_nodes(candidate, 1):
            return cmp.find_single_node(pe, candidate, 1, "rebuild")
    raise RuntimeError(f"rebuild has no node for 0x{module_id:08x}")


def to_set(ranges) -> set[int]:
    return {i for start, end, _ in ranges for i in range(start, end + 1)}


def to_ranges(offsets: set[int]) -> list[list[int]]:
    result: list[list[int]] = []
    for i in sorted(offsets):
        if result and result[-1][1] == i - 1:
            result[-1][1] = i
        else:
            result.append([i, i])
    return result


def declared_volatile(module: str) -> set[int]:
    path = Path(__file__).with_name("volatile") / f"{module}.json"
    if not path.exists():
        return set()
    return {i for start, end in json.loads(path.read_text(encoding="utf-8"))["ranges"] for i in range(start, end + 1)}


def compare(module: str, original: Path, node, rebuild: Path, rebuild_rva: int, noise_copy: Path, payload: bytes) -> dict:
    info, a, b = cmp.invoke_workers_with_powershell(original, node.worker_rva, rebuild, rebuild_rva, payload, 0x1000)
    noise: set[int] = set()
    for _ in range(NOISE_SAMPLES):
        _, n1, n2 = cmp.invoke_workers_with_powershell(original, node.worker_rva, noise_copy, node.worker_rva, payload, 0x1000)
        noise |= to_set(cmp.diff_ranges(n1, n2, 0x1000)[2])
    noise |= declared_volatile(module)
    real = to_set(cmp.diff_ranges(a, b, 0x1000)[2]) - noise
    envelope = all(info["original"][k] == info["rebuild"][k] for k in ("ret", "size"))
    return {
        "ok": not real and envelope,
        "ret": [info["original"]["ret"], info["rebuild"]["ret"]],
        "size": [info["original"]["size"], info["rebuild"]["size"]],
        "real_diff_bytes": len(real),
        "real_ranges": to_ranges(real)[:12],
        "noise_bytes": len(noise),
    }


def run_live(name: str, dll: str, folder: str, ids: list[int], pid_offset, work: Path) -> dict:
    research = RESEARCH / folder
    original = research / "module.dll"
    rebuild = BUILD / f"{dll}.dll"
    noise_copy = work / f"{dll}_noise.dll"
    shutil.copy2(original, noise_copy)
    pe_original, pe_rebuild = cmp.PeImage(original), cmp.PeImage(rebuild)

    packet = cmp.read_packet(research / "inputVacPacket_ScanId_4.bin")
    packet_node = cmp.find_single_node(pe_original, packet.module_id, packet.version, "packet")
    captured = cmp.ice_decrypt_buffer(packet_node.ice_key[:8], packet.encrypted_payload)
    if cmp.crc32_ieee(captured) != packet.crc32:
        raise RuntimeError("packet CRC mismatch")

    results: dict[str, dict] = {}
    for worker_id in ids:
        node = cmp.find_single_node(pe_original, worker_id, 1, "original")
        rva = find_node(pe_rebuild, worker_id).worker_rva
        if worker_id == packet.module_id:
            payload = bytes(captured)
        else:
            payload = bytes(captured[:32]) + bytes(len(captured) - 32)
        results[f"{worker_id:08x}/captured"] = compare(name, original, node, rebuild, rva, noise_copy, payload)
        if pid_offset is None:
            continue
        for label, pid in (("pid0", 0), ("pid4", 4), ("pid_bad", 0xFFFFFFFF)):
            patched = bytearray(payload)
            struct.pack_into("<I", patched, pid_offset, pid)
            results[f"{worker_id:08x}/{label}"] = compare(name, original, node, rebuild, rva, noise_copy, bytes(patched))
        target = subprocess.Popen(WOW64_TARGET, creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            time.sleep(1)
            patched = bytearray(payload)
            struct.pack_into("<I", patched, pid_offset, target.pid)
            results[f"{worker_id:08x}/pid_wow64"] = compare(name, original, node, rebuild, rva, noise_copy, bytes(patched))
        finally:
            target.terminate()
            target.wait()
    return results


DISPATCH_REPORT_LIMIT = {"timing_check": 0x20, "system_handles": 0x14}
DISPATCH_KNOWN = {"system_info": [(0x598, 0x59B, "address of the caller image, each side maps at its own base"),
                                  (0x5A0, 0x5A7, "reads +0x114 of the caller image, e_lfanew differs")]}
REPORT_SIZE = 0x1000
RESPONSE_SIZE = 0x1088


def session_ice_key() -> bytes:
    def step(value: int) -> int:
        next_value = (16807 * value - 0x7FFFFFFF * (value // 127773)) & 0xFFFFFFFF
        if next_value >= 0x80000000:
            next_value -= 1 << 32
        return next_value + 0x7FFFFFFF if next_value < 0 else next_value

    state, table = 1, [0] * 32
    for i in range(39, -1, -1):
        state = step(state)
        if i < 32:
            table[i] = state
    output, words = table[0], []
    for _ in range(4):
        state = step(state)
        bucket = output >> 26
        output = table[bucket]
        table[bucket] = state
        words.append(output)
    return struct.pack("<II", words[2], words[3])


def clear_response(path: Path, key: bytes) -> bytes:
    data = path.read_bytes()
    return cmp.ice_decrypt_buffer(key, data[:REPORT_SIZE]) + data[REPORT_SIZE:RESPONSE_SIZE]


def run_dispatch(name: str, dll: str, folder: str, work: Path) -> dict:
    research = RESEARCH / folder
    original, packet = research / "module.dll", research / "inputVacPacket_ScanId_4.bin"
    pairs = {"rebuild": BUILD / f"{dll}.dll", "noise": original}
    outputs: dict[str, str] = {}
    for label, other in pairs.items():
        dump = work / f"{name}_{label}"
        dump.mkdir(exist_ok=True)
        env = dict(os.environ, VAC_DISPATCH_DUMP=str(dump))
        proc = subprocess.run([str(TESTS / "dispatch_parity.exe"), str(original), str(other), str(packet)],
                              capture_output=True, text=True, env=env, timeout=300, errors="replace")
        outputs[label] = proc.stdout

    key = session_ice_key()
    limit = DISPATCH_REPORT_LIMIT.get(name, REPORT_SIZE)
    known = {i for start, end, _ in DISPATCH_KNOWN.get(name, []) for i in range(start, end + 1)}
    results: dict[str, dict] = {}
    for line in outputs["rebuild"].splitlines():
        match = re.match(r"(ok|FAIL)\s+(\w+)\s+result=(-?\d+)/(-?\d+) size=(\w+)/(\w+)", line)
        if not match:
            continue
        state, case, ret_a, ret_b, size_a, size_b = match.groups()
        envelope = ret_a == ret_b and size_a == size_b
        if case not in ("full_response", "other_session_id") or state == "ok":
            results[case] = {"ok": state == "ok", "exit": line[:90]}
            continue
        expected = clear_response(work / f"{name}_rebuild" / f"{case}.original.bin", key)
        actual = clear_response(work / f"{name}_rebuild" / f"{case}.rebuild.bin", key)
        first = clear_response(work / f"{name}_noise" / f"{case}.original.bin", key)
        second = clear_response(work / f"{name}_noise" / f"{case}.rebuild.bin", key)
        noise = {i for i in range(RESPONSE_SIZE) if first[i] != second[i]}
        ignored = noise | known | declared_volatile(name) | set(range(limit, REPORT_SIZE))
        real = {i for i in range(RESPONSE_SIZE) if expected[i] != actual[i]} - ignored
        results[case] = {"ok": not real and envelope, "real_diff_bytes": len(real), "real_ranges": to_ranges(real)[:12],
                         "noise_bytes": len(noise), "ret": [ret_a, ret_b]}
    if not results:
        results["error"] = {"ok": False, "exit": outputs["rebuild"][-200:]}
    return results


def write_system_info_input() -> None:
    research = RESEARCH / "ptr_0x0A00C948_crc_a07ed54b_GetSystemInfo"
    packet = cmp.read_packet(research / "inputVacPacket_ScanId_4.bin")
    node = cmp.find_single_node(cmp.PeImage(research / "module.dll"), packet.module_id, packet.version, "packet")
    (ROOT / "build/system_info_input.bin").write_bytes(cmp.ice_decrypt_buffer(node.ice_key[:8], packet.encrypted_payload))


def run_suite(command) -> dict:
    argv = [str(x) for x in command]
    try:
        proc = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=600, errors="replace")
    except subprocess.TimeoutExpired:
        return {"ok": False, "exit": "timeout", "tail": ""}
    tail = " | ".join((proc.stdout + proc.stderr).strip().splitlines()[-2:])[-240:]
    return {"ok": proc.returncode == 0, "exit": proc.returncode, "tail": tail}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--write-baseline", action="store_true")
    ap.add_argument("--no-suites", action="store_true")
    args = ap.parse_args()

    report: dict[str, dict] = {}
    with tempfile.TemporaryDirectory(prefix="vac_parity_") as td:
        for name, dll, folder, ids, pid_offset in MODULES:
            if args.only not in name:
                continue
            try:
                report[f"live:{name}"] = run_live(name, dll, folder, ids, pid_offset, Path(td))
            except Exception as exc:
                report[f"live:{name}"] = {"error": {"ok": False, "exit": str(exc)[:300]}}
        for name, dll, folder, _, _ in MODULES:
            if args.only not in name:
                continue
            try:
                report[f"dispatch:{name}"] = run_dispatch(name, dll, folder, Path(td))
            except Exception as exc:
                report[f"dispatch:{name}"] = {"error": {"ok": False, "exit": str(exc)[:300]}}
    if not args.no_suites:
        write_system_info_input()
        for name, command in SUITES:
            if args.only in name:
                key = f"suite:{name}:{Path(str(command[0])).stem if str(command[0]) != sys.executable else Path(str(command[1])).stem}"
                if "--live" in [str(x) for x in command]:
                    key += ":live"
                report[key] = {"run": run_suite(command)}

    baseline = json.loads(BASELINE.read_text()) if BASELINE.exists() else {}
    regressions = passed = failed = 0
    for key, cases in report.items():
        for case, result in cases.items():
            before = baseline.get(key, {}).get(case, {}).get("ok")
            state = "ok" if result["ok"] else "FAIL"
            passed += result["ok"]
            failed += not result["ok"]
            note = ""
            if not result["ok"]:
                note = f" diff={result.get('real_diff_bytes', '?')} ret={result.get('ret', '')} {result.get('real_ranges', '')[:4] if result.get('real_ranges') else ''} {result.get('exit', '')}"
                if before:
                    regressions += 1
                    note += "  <-- REGRESSION"
                elif before is False:
                    note += "  (also failed in baseline)"
            print(f"{state:4} {key} {case}{note}")
    print(f"\npassed={passed} failed={failed} regressions={regressions}")
    (ROOT / "build").mkdir(exist_ok=True)
    (ROOT / "build" / "parity_report.json").write_text(json.dumps(report, indent=1))
    if args.write_baseline:
        BASELINE.write_text(json.dumps(report, indent=1))
        print(f"baseline written: {BASELINE}")
    return 1 if regressions else 0


if __name__ == "__main__":
    raise SystemExit(main())
