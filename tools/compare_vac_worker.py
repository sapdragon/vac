#!/usr/bin/env python3
from __future__ import annotations

import argparse
import binascii
import json
import os
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


ICE_SXOR = (
    (0x83, 0x85, 0x9B, 0xCD),
    (0xCC, 0xA7, 0xAD, 0x41),
    (0x4B, 0x2E, 0xD4, 0x33),
    (0xEA, 0xCB, 0x2E, 0x04),
)

ICE_SMOD = (
    (333, 313, 505, 369),
    (379, 375, 319, 391),
    (361, 445, 451, 397),
    (397, 425, 395, 505),
)

ICE_PBOX = (
    0x00000001, 0x00000080, 0x00000400, 0x00002000,
    0x00080000, 0x00200000, 0x01000000, 0x40000000,
    0x00000008, 0x00000020, 0x00000100, 0x00004000,
    0x00010000, 0x00800000, 0x04000000, 0x20000000,
    0x00000004, 0x00000010, 0x00000200, 0x00008000,
    0x00020000, 0x00400000, 0x08000000, 0x10000000,
    0x00000002, 0x00000040, 0x00000800, 0x00001000,
    0x00040000, 0x00100000, 0x02000000, 0x80000000,
)

ICE_KEYROT = (
    0, 1, 2, 3, 2, 1, 3, 0,
    1, 3, 2, 0, 3, 1, 0, 2,
)


def u32(value: int) -> int:
    return value & 0xFFFFFFFF


def parse_int(text: str) -> int:
    return int(text, 0)


def read_u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def read_u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def gf_mult(a: int, b: int, mod: int) -> int:
    r = 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
        if a >= 0x100:
            a ^= mod
    return r


def gf_exp7(base: int, mod: int) -> int:
    if base == 0:
        return 0
    x = gf_mult(base, base, mod)
    x = gf_mult(base, x, mod)
    x = gf_mult(x, x, mod)
    return gf_mult(base, x, mod)


def permute32(x: int) -> int:
    r = 0
    for i in range(32):
        if x & 1:
            r |= ICE_PBOX[i]
        x >>= 1
        if not x:
            break
    return u32(r)


def make_sbox(idx: int) -> list[int]:
    box: list[int] = []
    for i in range(1024):
        col = (i >> 1) & 0xFF
        row = (i & 1) | ((i >> 8) & 2)
        b = col ^ ICE_SXOR[idx][row]
        ex = gf_exp7(b, ICE_SMOD[idx][row])
        box.append(permute32(ex << ((3 - idx) * 8)))
    return box


ICE_SBOXES = tuple(make_sbox(i) for i in range(4))


def ror32(x: int, n: int) -> int:
    return u32((x >> n) | (x << (32 - n)))


def ice_fround(p: int, sk: tuple[int, int, int]) -> int:
    tl = ((p >> 16) & 0x3FF) | (ror32(p, 14) & 0xFFC00)
    tr = (p & 0x3FF) | ((p & 0x3FF00) << 2)
    mask = sk[2] & (tl ^ tr)
    lt = tl ^ mask ^ sk[0]
    rt = tr ^ mask ^ sk[1]
    return u32(
        ICE_SBOXES[0][lt >> 10]
        ^ ICE_SBOXES[1][lt & 0x3FF]
        ^ ICE_SBOXES[2][rt >> 10]
        ^ ICE_SBOXES[3][rt & 0x3FF]
    )


def ice_schedule(key8: bytes) -> list[tuple[int, int, int]]:
    if len(key8) < 8:
        raise ValueError("ICE key must contain at least 8 bytes")
    kb = [0, 0, 0, 0]
    for j in range(4):
        kb[3 - j] = (key8[j * 2] << 8) | key8[j * 2 + 1]

    sched: list[tuple[int, int, int]] = [(0, 0, 0)] * 16
    for base in (0, 8):
        for i in range(8):
            rot = ICE_KEYROT[base + i]
            sk = [0, 0, 0]
            for j in range(15):
                dst = j % 3
                for k in range(4):
                    idx = (rot + k) & 3
                    bit = kb[idx] & 1
                    sk[dst] = (sk[dst] << 1) | bit
                    kb[idx] = ((kb[idx] >> 1) | ((bit ^ 1) << 15)) & 0xFFFF
            sched[base + i] = (sk[0], sk[1], sk[2])
    return sched


def ice_decrypt_block(schedule: list[tuple[int, int, int]], block: bytes) -> bytes:
    l = int.from_bytes(block[0:4], "big")
    r = int.from_bytes(block[4:8], "big")
    for i in range(16, 0, -2):
        l = u32(l ^ ice_fround(r, schedule[i - 1]))
        r = u32(r ^ ice_fround(l, schedule[i - 2]))
    return r.to_bytes(4, "big") + l.to_bytes(4, "big")


def ice_decrypt_buffer(key8: bytes, data: bytes) -> bytes:
    schedule = ice_schedule(key8[:8])
    out = bytearray(data)
    full = len(data) - (len(data) % 8)
    for off in range(0, full, 8):
        out[off:off + 8] = ice_decrypt_block(schedule, data[off:off + 8])
    return bytes(out)


@dataclass(frozen=True)
class Section:
    name: str
    va: int
    virtual_size: int
    raw_ptr: int
    raw_size: int
    characteristics: int


@dataclass(frozen=True)
class ModuleNode:
    node_rva: int
    module_id: int
    version: int
    worker_rva: int
    ice_key: bytes
    pnext_rva: int | None


class PeImage:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.data = path.read_bytes()
        if len(self.data) < 0x100 or self.data[:2] != b"MZ":
            raise ValueError(f"{path} is not a PE file")

        e_lfanew = read_u32(self.data, 0x3C)
        if self.data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            raise ValueError(f"{path} has an invalid PE signature")

        self.machine = read_u16(self.data, e_lfanew + 4)
        number_of_sections = read_u16(self.data, e_lfanew + 6)
        opt_size = read_u16(self.data, e_lfanew + 20)
        opt = e_lfanew + 24
        magic = read_u16(self.data, opt)
        if magic == 0x10B:
            self.bits = 32
            self.image_base = read_u32(self.data, opt + 28)
            self.size_of_image = read_u32(self.data, opt + 56)
            self.size_of_headers = read_u32(self.data, opt + 60)
        elif magic == 0x20B:
            self.bits = 64
            self.image_base = struct.unpack_from("<Q", self.data, opt + 24)[0]
            self.size_of_image = read_u32(self.data, opt + 56)
            self.size_of_headers = read_u32(self.data, opt + 60)
        else:
            raise ValueError(f"{path} has unsupported optional header magic 0x{magic:x}")

        sec_off = opt + opt_size
        self.sections: list[Section] = []
        for i in range(number_of_sections):
            off = sec_off + i * 40
            raw_name = self.data[off:off + 8].split(b"\0", 1)[0]
            name = raw_name.decode("ascii", "replace")
            self.sections.append(Section(
                name=name,
                virtual_size=read_u32(self.data, off + 8),
                va=read_u32(self.data, off + 12),
                raw_size=read_u32(self.data, off + 16),
                raw_ptr=read_u32(self.data, off + 20),
                characteristics=read_u32(self.data, off + 36),
            ))

    def file_offset_to_rva(self, file_off: int) -> int | None:
        if 0 <= file_off < self.size_of_headers:
            return file_off
        for sec in self.sections:
            if sec.raw_ptr <= file_off < sec.raw_ptr + sec.raw_size:
                return sec.va + (file_off - sec.raw_ptr)
        return None

    def rva_to_file_offset(self, rva: int) -> int | None:
        if 0 <= rva < self.size_of_headers:
            return rva
        for sec in self.sections:
            span = max(sec.raw_size, sec.virtual_size)
            if sec.va <= rva < sec.va + span:
                off = sec.raw_ptr + (rva - sec.va)
                if 0 <= off < len(self.data):
                    return off
        return None

    def va_or_rva_to_rva(self, value: int) -> int | None:
        if 0 <= value < self.size_of_image and self.rva_to_file_offset(value) is not None:
            return value
        if self.image_base <= value < self.image_base + self.size_of_image:
            rva = value - self.image_base
            if self.rva_to_file_offset(rva) is not None:
                return rva
        return None

    def section_for_rva(self, rva: int) -> Section | None:
        for sec in self.sections:
            span = max(sec.raw_size, sec.virtual_size)
            if sec.va <= rva < sec.va + span:
                return sec
        return None

    def is_executable_rva(self, rva: int) -> bool:
        sec = self.section_for_rva(rva)
        return bool(sec and (sec.characteristics & 0x20000000))

    def is_data_rva(self, rva: int) -> bool:
        sec = self.section_for_rva(rva)
        return bool(sec and (sec.name.startswith(".data") or not (sec.characteristics & 0x20000000)))

    def scan_nodes(self, module_id: int | None = None, version: int | None = None) -> list[ModuleNode]:
        nodes: list[ModuleNode] = []
        if self.bits != 32:
            return nodes
        for off in range(0, len(self.data) - 0x38, 4):
            try:
                pnext = read_u32(self.data, off)
                cur_id = read_u32(self.data, off + 4)
                cur_ver = read_u32(self.data, off + 8)
                fn = read_u32(self.data, off + 12)
            except struct.error:
                continue

            if module_id is not None and cur_id != module_id:
                continue
            if version is not None and cur_ver != version:
                continue
            if cur_id == 0 or cur_ver == 0:
                continue
            if cur_ver > 0x10000:
                continue

            worker_rva = self.va_or_rva_to_rva(fn)
            if worker_rva is None:
                continue
            if worker_rva == 0 or not self.is_executable_rva(worker_rva):
                continue
            pnext_rva = None
            if pnext:
                pnext_rva = self.va_or_rva_to_rva(pnext)
                if pnext_rva is None:
                    continue
            node_rva = self.file_offset_to_rva(off)
            if node_rva is None:
                continue
            if not self.is_data_rva(node_rva):
                continue

            ice_key = self.data[off + 16:off + 52]
            if len(ice_key) != 36:
                continue
            nodes.append(ModuleNode(node_rva, cur_id, cur_ver, worker_rva, ice_key, pnext_rva))
        return nodes


@dataclass(frozen=True)
class Packet:
    module_id: int
    version: int
    crc32: int
    payload_size: int
    encrypted_payload: bytes
    kind: str
    nonce: int | None = None


def read_packet(path: Path) -> Packet:
    data = path.read_bytes()
    if len(data) < 0x10:
        raise ValueError(f"{path} is too small for VacInputPacket_t")
    module_id, version, crc32, fourth = struct.unpack_from("<IIII", data, 0)

    if 0 < fourth <= len(data) - 0x10 and fourth % 8 == 0:
        payload_size = fourth
        end = 0x10 + payload_size
        return Packet(module_id, version, crc32, payload_size, data[0x10:end], "sized", None)

    if len(data) < 0xB0:
        raise ValueError(
            f"{path} is not a sized packet and is too small for fixed VAC input: 0x{len(data):x}"
        )
    payload_size = 0xA0
    return Packet(module_id, version, crc32, payload_size, data[0x10:0x10 + payload_size], "fixed", fourth)


def crc32_ieee(data: bytes) -> int:
    return binascii.crc32(data) & 0xFFFFFFFF


def parse_patch_u32(text: str) -> tuple[int, int]:
    if "=" not in text:
        raise argparse.ArgumentTypeError("expected OFFSET=VALUE")
    left, right = text.split("=", 1)
    return parse_int(left), parse_int(right)


def apply_patch_u32(payload: bytearray, off: int, value: int) -> None:
    if off < 0 or off + 4 > len(payload):
        raise ValueError(f"patch offset 0x{off:x} is outside payload size 0x{len(payload):x}")
    payload[off:off + 4] = struct.pack("<I", value & 0xFFFFFFFF)


def hexdump(data: bytes, count: int, prefix: str = "") -> str:
    lines = []
    count = min(count, len(data))
    for off in range(0, count, 16):
        chunk = data[off:off + 16]
        lines.append(f"{prefix}{off:04x}  " + " ".join(f"{b:02x}" for b in chunk))
    return "\n".join(lines)


def diff_ranges(a: bytes, b: bytes, limit: int) -> tuple[int, int | None, list[tuple[int, int, int]]]:
    n = min(limit, len(a), len(b))
    count = 0
    first: int | None = None
    ranges: list[tuple[int, int, int]] = []
    start: int | None = None
    end = -1
    for i in range(n):
        if a[i] != b[i]:
            count += 1
            if first is None:
                first = i
            if start is None:
                start = i
            end = i
        elif start is not None:
            ranges.append((start, end, end - start + 1))
            start = None
    if start is not None:
        ranges.append((start, end, end - start + 1))
    if len(a) != len(b) and limit > n:
        extra = min(limit, max(len(a), len(b))) - n
        if extra > 0:
            count += extra
            if first is None:
                first = n
            ranges.append((n, n + extra - 1, extra))
    return count, first, ranges


POWERSHELL_HELPER = r'''
param(
    [string]$OriginalDll,
    [UInt32]$OriginalRva,
    [string]$RebuildDll,
    [UInt32]$RebuildRva,
    [string]$PayloadPath,
    [UInt32]$OutSize,
    [string]$OriginalOutPath,
    [string]$RebuildOutPath
)

$ErrorActionPreference = 'Stop'

$src = @'
using System;
using System.Runtime.InteropServices;

public static class VacWorkerNative {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr LoadLibrary(string path);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool SetDllDirectory(string path);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern UInt32 GetLastError();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(IntPtr address, UIntPtr size, UInt32 type, UInt32 protect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualFree(IntPtr address, UIntPtr size, UInt32 type);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtect(IntPtr address, UIntPtr size, UInt32 protect, out UInt32 old);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int Worker(IntPtr input, IntPtr output, ref UInt32 outputSize);
}
'@

Add-Type $src

function Invoke-VacWorker([string]$DllPath, [UInt32]$WorkerRva, [byte[]]$Payload, [UInt32]$OutCap, [string]$OutPath) {
    $dir = [System.IO.Path]::GetDirectoryName($DllPath)
    if ($dir) { [VacWorkerNative]::SetDllDirectory($dir) | Out-Null }

    $h = [VacWorkerNative]::LoadLibrary($DllPath)
    if ($h -eq [IntPtr]::Zero) {
        throw "LoadLibrary failed for $DllPath, win32=$([VacWorkerNative]::GetLastError())"
    }

    $ntHeaders = [Runtime.InteropServices.Marshal]::ReadInt32($h, 0x3C)
    $imageSize = [Runtime.InteropServices.Marshal]::ReadInt32($h, $ntHeaders + 0x50)
    [UInt32]$oldProtect = 0
    [VacWorkerNative]::VirtualProtect($h, [UIntPtr]::new($imageSize), 0x40, [ref]$oldProtect) | Out-Null

    $fn = [IntPtr]($h.ToInt64() + [Int64]$WorkerRva)
    $worker = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        $fn, [type][VacWorkerNative+Worker])

    # Several original workers accept a small advertised capacity but clear 4096 bytes.
    # Same protection as the dispatcher sandbox. The original image is mapped RWX by
    # VAC's own loader, which workers with self-modifying stubs depend on.
    $outLen = [Math]::Max(4096, $OutCap)
    $sandbox = [VacWorkerNative]::VirtualAlloc([IntPtr]::Zero, [UIntPtr]::new($outLen), 0x3000, 0x04)
    if ($sandbox -eq [IntPtr]::Zero) { throw "VirtualAlloc failed" }
    # Some original workers mutate their decrypted input (for example a path).
    # Each side must receive its own copy of the same initial payload.
    [byte[]]$localPayload = $Payload.Clone()
    $pinInput = [Runtime.InteropServices.GCHandle]::Alloc($localPayload, [Runtime.InteropServices.GCHandleType]::Pinned)
    try {
        [UInt32]$size = $OutCap
        $ret = $worker.Invoke($pinInput.AddrOfPinnedObject(), $sandbox, [ref]$size)
        [byte[]]$output = New-Object byte[] $outLen
        [Runtime.InteropServices.Marshal]::Copy($sandbox, $output, 0, $outLen)
        [System.IO.File]::WriteAllBytes($OutPath, $output)
        return [pscustomobject]@{
            ret = $ret
            size = $size
            base = ('0x{0:x8}' -f $h.ToInt64())
            worker = ('0x{0:x}' -f $WorkerRva)
        }
    } finally {
        $pinInput.Free()
        [VacWorkerNative]::VirtualFree($sandbox, [UIntPtr]::Zero, 0x8000) | Out-Null
    }
}

$payload = [System.IO.File]::ReadAllBytes($PayloadPath)
$result = [pscustomobject]@{
    original = Invoke-VacWorker $OriginalDll $OriginalRva $payload $OutSize $OriginalOutPath
    rebuild = Invoke-VacWorker $RebuildDll $RebuildRva $payload $OutSize $RebuildOutPath
}
$result | ConvertTo-Json -Compress
'''


def invoke_workers_with_powershell(
    original_dll: Path,
    original_rva: int,
    rebuild_dll: Path,
    rebuild_rva: int,
    payload: bytes,
    out_size: int,
) -> tuple[dict, bytes, bytes]:
    system_root = Path(os.environ.get("WINDIR", r"C:\Windows"))
    powershell = system_root / "SysWOW64" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if not powershell.exists():
        raise RuntimeError(f"32-bit PowerShell not found at {powershell}")

    with tempfile.TemporaryDirectory(prefix="vac_worker_cmp_") as td:
        tmp = Path(td)
        helper = tmp / "invoke_worker.ps1"
        payload_path = tmp / "payload.bin"
        original_out = tmp / "original_worker.bin"
        rebuild_out = tmp / "rebuild_worker.bin"
        helper.write_text(POWERSHELL_HELPER, encoding="utf-8")
        payload_path.write_bytes(payload)

        cmd = [
            str(powershell),
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(helper),
            str(original_dll),
            str(original_rva),
            str(rebuild_dll),
            str(rebuild_rva),
            str(payload_path),
            str(out_size),
            str(original_out),
            str(rebuild_out),
        ]
        proc = subprocess.run(cmd, text=True, capture_output=True)
        if proc.returncode != 0:
            raise RuntimeError(
                "worker helper failed\n"
                f"stdout:\n{proc.stdout}\n"
                f"stderr:\n{proc.stderr}"
            )
        lines = [line for line in proc.stdout.splitlines() if line.strip()]
        if not lines:
            raise RuntimeError("worker helper produced no JSON output")
        info = json.loads(lines[-1])
        return info, original_out.read_bytes(), rebuild_out.read_bytes()


def find_single_node(pe: PeImage, module_id: int, version: int, label: str) -> ModuleNode:
    nodes = pe.scan_nodes(module_id, version)
    if not nodes:
        raise RuntimeError(f"{label}: no module node found for id=0x{module_id:08x}, version=0x{version:x}")
    if len(nodes) > 1:
        print(f"{label}: warning: found {len(nodes)} matching nodes, using first", file=sys.stderr)
    return nodes[0]


def print_node(label: str, path: Path, pe: PeImage, node: ModuleNode) -> None:
    print(
        f"{label}: {path} imageBase=0x{pe.image_base:08x} "
        f"nodeRva=0x{node.node_rva:x} workerRva=0x{node.worker_rva:x} "
        f"id=0x{node.module_id:08x} version=0x{node.version:x}"
    )


def inventory_summary(label: str, data: bytes) -> None:
    if len(data) < 0x58:
        return
    status = read_u32(data, 0x10)
    process_flags = read_u32(data, 0x14)
    last_error = read_u32(data, 0x18)
    target_pid = read_u32(data, 0x1C)
    modules = read_u32(data, 0x24)
    packed = read_u32(data, 0x3C)
    string_size = read_u16(data, 0x4E)
    comp = read_u32(data, 0x50)
    plain = read_u32(data, 0x54)
    print(
        f"{label}: status=0x{status:x} processFlags=0x{process_flags:08x} "
        f"lastError=0x{last_error:x} pid={target_pid} modules={modules} "
        f"packed={packed} strings={string_size} comp={comp} plain={plain}"
    )


def list_nodes(paths: Iterable[str]) -> int:
    for raw in paths:
        path = Path(raw).expanduser().resolve()
        pe = PeImage(path)
        print(f"{path} imageBase=0x{pe.image_base:08x} bits={pe.bits}")
        nodes = pe.scan_nodes()
        if not nodes:
            print("  no nodes found")
            continue
        for node in nodes:
            pnext = "none" if node.pnext_rva is None else f"0x{node.pnext_rva:x}"
            key = node.ice_key[:8].hex(" ")
            print(
                f"  nodeRva=0x{node.node_rva:x} id=0x{node.module_id:08x} "
                f"version=0x{node.version:x} workerRva=0x{node.worker_rva:x} "
                f"pNext={pnext} iceKey={key}"
            )
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Compare direct VAC worker outputs before dispatcher encryption.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Example for process_memory_map:\n"
            "  py tools\\compare_vac_worker.py \\\n"
            "    --original C:\\path\\vac_runner\\module.dll \\\n"
            "    --rebuild build\\Release\\Win32\\process_memory_map.dll \\\n"
            "    --packet C:\\path\\vac_runner\\input_packet.bin \\\n"
            "    --spawn C:\\Windows\\System32\\notepad.exe --patch-pid-offset 0x60 \\\n"
            "    --inventory-summary --dump-dir C:\\tmp\\vac_cmp\n"
        ),
    )
    p.add_argument("--list-nodes", nargs="+", help="List candidate vac_module_node_t records and exit.")
    p.add_argument("--original", help="Original module DLL.")
    p.add_argument("--rebuild", help="Rebuilt module DLL.")
    p.add_argument("--packet", help="VAC input_packet.bin. Used to get id/version and decrypt payload.")
    p.add_argument("--payload-decrypted", help="Raw decrypted worker payload. Requires --module-id if no --packet.")
    p.add_argument("--module-id", type=parse_int, help="Override module id.")
    p.add_argument("--module-version", type=parse_int, help="Override module version.")
    p.add_argument("--patch-u32", action="append", type=parse_patch_u32, default=[],
                   help="Patch decrypted payload dword: OFFSET=VALUE. Can be repeated.")
    p.add_argument("--spawn", help="Spawn a temporary process before worker call.")
    p.add_argument("--patch-pid-offset", type=parse_int,
                   help="Patch spawned process PID at this decrypted payload offset.")
    p.add_argument("--wait-ms", type=int, default=300, help="Delay after --spawn before calling workers.")
    p.add_argument("--out-size", type=parse_int, default=0x1000, help="Worker output buffer size.")
    p.add_argument("--compare-size", type=parse_int, help="Number of output bytes to compare. Defaults to --out-size.")
    p.add_argument("--hexdump", type=parse_int, default=0x90, help="Hexdump this many bytes from both outputs. 0 disables.")
    p.add_argument("--inventory-summary", action="store_true",
                   help="Print process_memory_map field summary.")
    p.add_argument("--dump-dir", help="Write payload and worker outputs to this directory.")
    p.add_argument("--decrypt-only", action="store_true",
                   help="Stop after packet decrypt/patch/dump; do not load or execute DLL workers.")
    p.add_argument("--no-crc-check", action="store_true", help="Do not fail on decrypted payload CRC mismatch.")
    return p


def main(argv: list[str]) -> int:
    args = build_arg_parser().parse_args(argv)

    if args.list_nodes:
        return list_nodes(args.list_nodes)

    if not args.original or not args.rebuild:
        raise SystemExit("--original and --rebuild are required")
    if bool(args.packet) == bool(args.payload_decrypted):
        raise SystemExit("provide exactly one of --packet or --payload-decrypted")

    original_path = Path(args.original).expanduser().resolve()
    rebuild_path = Path(args.rebuild).expanduser().resolve()
    original_pe = PeImage(original_path)
    rebuild_pe = PeImage(rebuild_path)

    packet: Packet | None = None
    if args.packet:
        packet = read_packet(Path(args.packet).expanduser().resolve())
        module_id = packet.module_id if args.module_id is None else args.module_id
        version = packet.version if args.module_version is None else args.module_version
    else:
        if args.module_id is None:
            raise SystemExit("--module-id is required with --payload-decrypted")
        module_id = args.module_id
        version = 1 if args.module_version is None else args.module_version

    original_node = find_single_node(original_pe, module_id, version, "original")
    rebuild_node = find_single_node(rebuild_pe, module_id, version, "rebuild")
    print_node("original", original_path, original_pe, original_node)
    print_node("rebuild ", rebuild_path, rebuild_pe, rebuild_node)

    if packet:
        decrypted = ice_decrypt_buffer(original_node.ice_key[:8], packet.encrypted_payload)
        actual_crc = crc32_ieee(decrypted)
        nonce = "" if packet.nonce is None else f" nonce=0x{packet.nonce:08x}"
        print(
            f"packet: id=0x{packet.module_id:08x} version=0x{packet.version:x} "
            f"format={packet.kind}{nonce} payloadSize=0x{packet.payload_size:x} "
            f"crc=0x{packet.crc32:08x} actual=0x{actual_crc:08x}"
        )
        if actual_crc != packet.crc32 and not args.no_crc_check:
            raise RuntimeError("decrypted payload CRC mismatch")
        if rebuild_node.ice_key[:8] != original_node.ice_key[:8]:
            print("warning: original and rebuild module ICE keys differ", file=sys.stderr)
    else:
        decrypted = Path(args.payload_decrypted).expanduser().resolve().read_bytes()
        print(f"payload: decrypted file size=0x{len(decrypted):x}")

    payload = bytearray(decrypted)
    if args.decrypt_only and args.spawn:
        raise SystemExit("--decrypt-only cannot be combined with --spawn")
    spawned: subprocess.Popen | None = None
    try:
        patches = list(args.patch_u32)
        if args.spawn:
            if args.patch_pid_offset is None:
                raise SystemExit("--spawn requires --patch-pid-offset")
            spawn_path = os.path.expandvars(args.spawn)
            startupinfo = None
            if os.name == "nt":
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = 0
            spawned = subprocess.Popen([spawn_path], startupinfo=startupinfo)
            time.sleep(max(args.wait_ms, 0) / 1000.0)
            patches.append((args.patch_pid_offset, spawned.pid))
            print(f"spawned: pid={spawned.pid} path={spawn_path}")

        for off, value in patches:
            apply_patch_u32(payload, off, value)
            print(f"patch: u32[0x{off:x}] = 0x{value & 0xFFFFFFFF:08x}")

        if args.decrypt_only:
            if args.hexdump:
                print("patched payload hexdump:")
                print(hexdump(payload, args.hexdump, "  "))
            if args.dump_dir:
                dump_dir = Path(args.dump_dir).expanduser().resolve()
                dump_dir.mkdir(parents=True, exist_ok=True)
                (dump_dir / "decrypted_payload.bin").write_bytes(decrypted)
                (dump_dir / "patched_payload.bin").write_bytes(payload)
                meta = {
                    "module_id": f"0x{module_id:08x}",
                    "module_version": f"0x{version:x}",
                    "original_node_rva": f"0x{original_node.node_rva:x}",
                    "original_worker_rva": f"0x{original_node.worker_rva:x}",
                    "rebuild_node_rva": f"0x{rebuild_node.node_rva:x}",
                    "rebuild_worker_rva": f"0x{rebuild_node.worker_rva:x}",
                    "packet_format": None if packet is None else packet.kind,
                    "packet_nonce": None if packet is None or packet.nonce is None else f"0x{packet.nonce:08x}",
                    "patches": [(f"0x{o:x}", f"0x{v & 0xFFFFFFFF:08x}") for o, v in patches],
                }
                (dump_dir / "compare_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
                print(f"dumped: {dump_dir}")
            return 0

        helper_info, original_out, rebuild_out = invoke_workers_with_powershell(
            original_path,
            original_node.worker_rva,
            rebuild_path,
            rebuild_node.worker_rva,
            bytes(payload),
            args.out_size,
        )
    finally:
        if spawned is not None and spawned.poll() is None:
            spawned.terminate()
            try:
                spawned.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                spawned.kill()

    print(
        f"original: ret={helper_info['original']['ret']} size={helper_info['original']['size']} "
        f"base={helper_info['original']['base']} workerRva={helper_info['original']['worker']}"
    )
    print(
        f"rebuild : ret={helper_info['rebuild']['ret']} size={helper_info['rebuild']['size']} "
        f"base={helper_info['rebuild']['base']} workerRva={helper_info['rebuild']['worker']}"
    )

    if args.inventory_summary:
        inventory_summary("original", original_out)
        inventory_summary("rebuild ", rebuild_out)

    compare_size = args.compare_size if args.compare_size is not None else args.out_size
    diff_count, first_diff, ranges = diff_ranges(original_out, rebuild_out, compare_size)
    envelope_equal = all(helper_info['original'][field] == helper_info['rebuild'][field]
                         for field in ('ret', 'size'))
    first_text = "none" if first_diff is None else f"0x{first_diff:x}"
    print(f"diffCount={diff_count} firstDiff={first_text}")
    if diff_count:
        shown = " ".join(f"0x{s:x}-0x{e:x}:{n}" for s, e, n in ranges[:20])
        print(f"diffRanges={shown}")

    if args.hexdump:
        print("original hexdump:")
        print(hexdump(original_out, args.hexdump, "  "))
        print("rebuild hexdump:")
        print(hexdump(rebuild_out, args.hexdump, "  "))

    if args.dump_dir:
        dump_dir = Path(args.dump_dir).expanduser().resolve()
        dump_dir.mkdir(parents=True, exist_ok=True)
        (dump_dir / "decrypted_payload.bin").write_bytes(decrypted)
        (dump_dir / "patched_payload.bin").write_bytes(payload)
        (dump_dir / "original_worker.bin").write_bytes(original_out)
        (dump_dir / "rebuild_worker.bin").write_bytes(rebuild_out)
        meta = {
            "module_id": f"0x{module_id:08x}",
            "module_version": f"0x{version:x}",
            "original_node_rva": f"0x{original_node.node_rva:x}",
            "original_worker_rva": f"0x{original_node.worker_rva:x}",
            "rebuild_node_rva": f"0x{rebuild_node.node_rva:x}",
            "rebuild_worker_rva": f"0x{rebuild_node.worker_rva:x}",
            "diff_count": diff_count,
            "envelope_equal": envelope_equal,
            "original_return": helper_info['original']['ret'],
            "rebuild_return": helper_info['rebuild']['ret'],
            "original_size": helper_info['original']['size'],
            "rebuild_size": helper_info['rebuild']['size'],
            "first_diff": None if first_diff is None else f"0x{first_diff:x}",
            "patches": [(f"0x{o:x}", f"0x{v & 0xFFFFFFFF:08x}") for o, v in patches],
        }
        (dump_dir / "compare_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        print(f"dumped: {dump_dir}")

    return 0 if diff_count == 0 and envelope_equal else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
