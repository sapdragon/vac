#!/usr/bin/env python3
from __future__ import annotations

import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
import compare_vac_worker as compare

ORIGINAL = ROOT.parent / "vac-research/ptr_0x0D2058E8_crc_8d88e017_ProcessScan_QVM_PEB"
TARGET = ROOT / "build/tests/process_memory_map_regression.exe"
FIXTURE = ROOT / "build/process_memory_map_crafted_files"
DUMPS = ROOT / "build/vac_cmp_process_memory_map_crafted"
SOURCE_NAMES = {0: "raw file", 4: "memory", 8: "normalized file"}


def lz4_decompress(data: bytes, size: int) -> bytes:
    out = bytearray()
    i = 0
    while i < len(data):
        token = data[i]
        i += 1
        length = token >> 4
        if length == 15:
            while True:
                extra = data[i]
                i += 1
                length += extra
                if extra != 255:
                    break
        out += data[i:i + length]
        i += length
        if i >= len(data) or len(out) >= size:
            break
        offset = data[i] | data[i + 1] << 8
        i += 2
        length = token & 15
        if length == 15:
            while True:
                extra = data[i]
                i += 1
                length += extra
                if extra != 255:
                    break
        length += 4
        for _ in range(length):
            out.append(out[-offset])
    return bytes(out)


def summarize(report: bytes) -> None:
    count_hashes = report[0x48]
    records, strings = struct.unpack_from("<HH", report, 0x4C)
    compressed, plain = struct.unpack_from("<II", report, 0x50)
    wide = bool(struct.unpack_from("<H", report, 0x4A)[0] & 4)
    blob = lz4_decompress(report[0x58:0x58 + compressed], plain)
    width = 36 if wide else 32
    print(f"  status={struct.unpack_from('<I', report, 0x10)[0]} records={records} hashes={count_hashes} strings={strings} plain={plain}")
    tally: dict[str, int] = {}
    for row in range(count_hashes):
        source = struct.unpack_from("<I", blob, row * width)[0] & 0xFFF
        name = SOURCE_NAMES.get(source, hex(source))
        tally[name] = tally.get(name, 0) + 1
    print("  hash rows by source:", tally)
    record_width = 20 if wide else 16
    flags = [struct.unpack_from("<I", blob, count_hashes * width + i * record_width + record_width - 4)[0] & 0xFFF
             for i in range(records)]
    print("  record flags seen:", sorted({hex(x) for x in flags}))


def main() -> int:
    FIXTURE.mkdir(parents=True, exist_ok=True)
    target = subprocess.Popen([str(TARGET), "--crafted-target", str(FIXTURE)], stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    failures = 0
    try:
        ready = target.stdout.readline().strip()
        if ready != "ready":
            print(f"target failed: {ready}")
            return 2
        cases = [
            ("all_hashes", ["--patch-u32", "0x68=32", "--patch-u32", "0x70=0"]),
            ("high_scan_start", ["--patch-u32", "0x68=32", "--patch-u32", "0x70=0", "--patch-u32", "0x64=0x10000"]),
            ("no_hashes", ["--patch-u32", "0x68=0"]),
            ("trim_one", ["--patch-u32", "0x68=32", "--patch-u32", "0x70=0", "--patch-u32", "0x6c=1"]),
        ]
        for name, patches in cases:
            dump = DUMPS / name
            print(f"== {name}")
            result = compare.main([
                "--original", str(ORIGINAL / "module.dll"),
                "--rebuild", str(ROOT / "build/Release/Win32/process_memory_map.dll"),
                "--packet", str(ORIGINAL / "inputVacPacket_ScanId_4.bin"),
                "--patch-u32", f"0x60={target.pid}",
                "--hexdump", "0",
                "--dump-dir", str(dump),
            ] + patches)
            print(f"  compare exit={result}")
            failures += result != 0
            original = dump / "original_worker.bin"
            if original.exists():
                summarize(original.read_bytes())
    finally:
        target.terminate()
        target.wait()
    print(f"failures={failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
