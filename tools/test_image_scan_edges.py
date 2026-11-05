#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ctypes
import os
import re
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMPARE = ROOT / "tools" / "compare_vac_worker.py"

DEFAULT_ORIGINAL = Path(
    r"C:\Users\User\Documents\GitHub\vac-research"
    r"\ptr_0x0D047AF0_crc_33211402_GameCryptoVerify\module.dll"
)
DEFAULT_PACKET = Path(
    r"C:\Users\User\Documents\GitHub\vac-research"
    r"\ptr_0x0D047AF0_crc_33211402_GameCryptoVerify"
    r"\inputVacPacket_ScanId_4.bin"
)
DEFAULT_REBUILD = ROOT / "build" / "Release" / "Win32" / "image_scan.dll"

OFF_FLAGS = 0x20
OFF_PID = 0x60
OFF_TARGET_LO = 0x64
OFF_TARGET_HI = 0x68
OFF_TARGET_SIZE = 0x6C

OUT_MAPPED_NAME = 0x828
OUT_PE_HEADERS = 0xE18
PE_CATALOG_VALID = OUT_PE_HEADERS + 0x104
PE_POLICY_OK = OUT_PE_HEADERS + 0x105
PE_WINTRUST_STATUS = OUT_PE_HEADERS + 0x120
PE_CATALOG_STATUS = OUT_PE_HEADERS + 0x124
PE_CATALOG_PATH = OUT_PE_HEADERS + 0x128


@dataclass
class CaseResult:
    name: str
    returncode: int
    diff_count: int | None
    first_diff: str | None
    dump_dir: Path
    catalog_valid: int | None = None
    wintrust_status: int | None = None
    catalog_status: int | None = None
    mapped_name: str = ""
    catalog_path: str = ""


class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", ctypes.c_uint32),
        ("ftCreationTimeLow", ctypes.c_uint32),
        ("ftCreationTimeHigh", ctypes.c_uint32),
        ("ftLastAccessTimeLow", ctypes.c_uint32),
        ("ftLastAccessTimeHigh", ctypes.c_uint32),
        ("ftLastWriteTimeLow", ctypes.c_uint32),
        ("ftLastWriteTimeHigh", ctypes.c_uint32),
        ("dwVolumeSerialNumber", ctypes.c_uint32),
        ("nFileSizeHigh", ctypes.c_uint32),
        ("nFileSizeLow", ctypes.c_uint32),
        ("nNumberOfLinks", ctypes.c_uint32),
        ("nFileIndexHigh", ctypes.c_uint32),
        ("nFileIndexLow", ctypes.c_uint32),
    ]


class MODULEINFO(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
        ("SizeOfImage", ctypes.c_uint32),
        ("EntryPoint", ctypes.c_void_p),
    ]


def u32(value: int) -> int:
    return value & 0xFFFFFFFF


def split_u64(value: int) -> tuple[int, int]:
    return u32(value), u32(value >> 32)


def c_string(raw: bytes) -> str:
    raw = raw.split(b"\0", 1)[0]
    return raw.decode("utf-8", errors="backslashreplace")


def inspect_dump(dump_dir: Path, result: CaseResult) -> None:
    path = dump_dir / "original_worker.bin"
    if not path.exists():
        return
    data = path.read_bytes()
    if len(data) <= PE_CATALOG_STATUS + 4:
        return
    result.catalog_valid = data[PE_CATALOG_VALID]
    result.wintrust_status = struct.unpack_from("<I", data, PE_WINTRUST_STATUS)[0]
    result.catalog_status = struct.unpack_from("<I", data, PE_CATALOG_STATUS)[0]
    result.mapped_name = c_string(data[OUT_MAPPED_NAME:OUT_MAPPED_NAME + 0x100])
    result.catalog_path = c_string(data[PE_CATALOG_PATH:PE_CATALOG_PATH + 119])


def run_compare(
    *,
    python: Path,
    original: Path,
    rebuild: Path,
    packet: Path,
    dump_root: Path,
    name: str,
    patches: list[tuple[int, int]],
) -> CaseResult:
    dump_dir = dump_root / name
    cmd = [
        str(python),
        str(COMPARE),
        "--original",
        str(original),
        "--rebuild",
        str(rebuild),
        "--packet",
        str(packet),
        "--out-size",
        "0x1000",
        "--compare-size",
        "0x1000",
        "--hexdump",
        "0",
        "--dump-dir",
        str(dump_dir),
    ]
    for off, value in patches:
        cmd.extend(["--patch-u32", f"0x{off:x}=0x{u32(value):x}"])

    print(f"\n=== {name} ===", flush=True)
    proc = subprocess.run(cmd, text=True, capture_output=True)
    if proc.stdout:
        print(proc.stdout.rstrip())
    if proc.stderr:
        print(proc.stderr.rstrip(), file=sys.stderr)

    diff_count: int | None = None
    first_diff: str | None = None
    m = re.search(r"diffCount=(\d+)\s+firstDiff=([^\s]+)", proc.stdout)
    if m:
        diff_count = int(m.group(1))
        first_diff = m.group(2)

    result = CaseResult(name, proc.returncode, diff_count, first_diff, dump_dir)
    inspect_dump(dump_dir, result)
    return result


def external_patches(pid: int, address: int = 0, size: int = 0) -> list[tuple[int, int]]:
    lo, hi = split_u64(address)
    return [
        (OFF_PID, pid),
        (OFF_TARGET_LO, lo),
        (OFF_TARGET_HI, hi),
        (OFF_TARGET_SIZE, size),
    ]


def local_file_patches(file_id: int, volume_serial: int) -> list[tuple[int, int]]:
    lo, hi = split_u64(file_id)
    return [
        (OFF_FLAGS, 0),
        (OFF_PID, 0),
        (OFF_TARGET_LO, lo),
        (OFF_TARGET_HI, hi),
        (OFF_TARGET_SIZE, volume_serial),
    ]


def spawn_hidden(argv: list[str]) -> subprocess.Popen:
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = 0
    return subprocess.Popen(argv, startupinfo=startupinfo)


def file_id_and_volume(path: Path) -> tuple[int, int]:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    CreateFileW = kernel32.CreateFileW
    CreateFileW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    CreateFileW.restype = ctypes.c_void_p
    GetFileInformationByHandle = kernel32.GetFileInformationByHandle
    GetFileInformationByHandle.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(BY_HANDLE_FILE_INFORMATION),
    ]
    GetFileInformationByHandle.restype = ctypes.c_int
    CloseHandle = kernel32.CloseHandle

    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 0x1
    FILE_SHARE_WRITE = 0x2
    FILE_SHARE_DELETE = 0x4
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x80
    invalid = ctypes.c_void_p(-1).value

    h = CreateFileW(
        str(path),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if h == invalid:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        info = BY_HANDLE_FILE_INFORMATION()
        if not GetFileInformationByHandle(h, ctypes.byref(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        file_id = (int(info.nFileIndexHigh) << 32) | int(info.nFileIndexLow)
        return file_id, int(info.dwVolumeSerialNumber)
    finally:
        CloseHandle(h)


def load_module_info(dll_name_or_path: str) -> tuple[int, int]:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)

    kernel32.LoadLibraryW.argtypes = [ctypes.c_wchar_p]
    kernel32.LoadLibraryW.restype = ctypes.c_void_p
    kernel32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
    kernel32.GetModuleHandleW.restype = ctypes.c_void_p
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    psapi.GetModuleInformation.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(MODULEINFO),
        ctypes.c_uint32,
    ]
    psapi.GetModuleInformation.restype = ctypes.c_int

    hmod = kernel32.GetModuleHandleW(dll_name_or_path)
    if not hmod:
        hmod = kernel32.LoadLibraryW(dll_name_or_path)
    if not hmod:
        raise ctypes.WinError(ctypes.get_last_error())

    info = MODULEINFO()
    if not psapi.GetModuleInformation(
        kernel32.GetCurrentProcess(), hmod, ctypes.byref(info), ctypes.sizeof(info)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    return int(info.lpBaseOfDll), int(info.SizeOfImage)


def allocate_private_exec_region() -> tuple[int, int]:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.VirtualAlloc.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_uint32,
        ctypes.c_uint32,
    ]
    kernel32.VirtualAlloc.restype = ctypes.c_void_p

    size = 0x3000
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    PAGE_EXECUTE_READWRITE = 0x40
    ptr = kernel32.VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not ptr:
        raise ctypes.WinError(ctypes.get_last_error())
    buf = (ctypes.c_ubyte * size).from_address(ptr)
    for i in range(size):
        buf[i] = 0x90
    marker = b"VAC_PRIVATE_EXEC_REGION_NO_MAPPED_FILE"
    for i, b in enumerate(marker):
        buf[0x100 + i] = b
    return int(ptr), size


def write_test_files(root: Path) -> dict[str, Path]:
    root.mkdir(parents=True, exist_ok=True)
    files: dict[str, Path] = {}

    files["invalid_not_mz"] = root / "invalid_not_mz.bin"
    files["invalid_not_mz"].write_bytes(b"not a PE image\n" * 8)

    mz = bytearray(0x80)
    mz[0:2] = b"MZ"
    struct.pack_into("<I", mz, 0x3C, 0x200)
    files["stripped_mz_no_pe"] = root / "stripped_mz_no_pe.bin"
    files["stripped_mz_no_pe"].write_bytes(mz)

    files["invalid_optional_magic"] = root / "invalid_optional_magic.exe"
    files["invalid_optional_magic"].write_bytes(make_minimal_pe(opt_magic=0))

    files["weird_sections"] = root / "weird_sections.exe"
    files["weird_sections"].write_bytes(make_minimal_pe(weird_section=True))

    return files


def make_minimal_pe(opt_magic: int = 0x10B, weird_section: bool = False) -> bytes:
    data = bytearray(0x420)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    off = 0x80
    data[off:off + 4] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH",
        data,
        off + 4,
        0x14C,
        1,
        0x5E2A5A00,
        0,
        0,
        0xE0,
        0x010F,
    )
    opt = off + 24
    struct.pack_into("<H", data, opt, opt_magic)
    struct.pack_into("<I", data, opt + 16, 0x1000)
    struct.pack_into("<I", data, opt + 28, 0x400000)
    struct.pack_into("<I", data, opt + 32, 0x1000)
    struct.pack_into("<I", data, opt + 36, 0x200)
    struct.pack_into("<H", data, opt + 68, 3)
    struct.pack_into("<I", data, opt + 56, 0x2000)
    struct.pack_into("<I", data, opt + 60, 0x200)
    struct.pack_into("<I", data, opt + 92, 16)

    sec = opt + 0xE0
    data[sec:sec + 8] = b".text\0\0\0"
    if weird_section:
        virtual_size, virtual_address, raw_size, raw_ptr = 0x10, 0x70000000, 0x800, 0x6000
    else:
        virtual_size, virtual_address, raw_size, raw_ptr = 0x20, 0x1000, 0x200, 0x200
    struct.pack_into("<IIIIIIHHI", data, sec + 8, virtual_size, virtual_address,
                     raw_size, raw_ptr, 0, 0, 0, 0, 0x60000020)
    data[0x200:0x210] = b"\xCC" * 0x10
    return bytes(data)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--original", type=Path, default=DEFAULT_ORIGINAL)
    p.add_argument("--rebuild", type=Path, default=DEFAULT_REBUILD)
    p.add_argument("--packet", type=Path, default=DEFAULT_PACKET)
    p.add_argument("--python", type=Path, default=Path(sys.executable))
    p.add_argument("--dump-root", type=Path, default=ROOT / "build" / "image_scan_edge_cases")
    p.add_argument("--skip-local-files", action="store_true")
    args = p.parse_args()

    args.dump_root.mkdir(parents=True, exist_ok=True)
    results: list[CaseResult] = []
    spawned: list[subprocess.Popen] = []

    def case(name: str, patches: list[tuple[int, int]]) -> CaseResult:
        result = run_compare(
            python=args.python,
            original=args.original,
            rebuild=args.rebuild,
            packet=args.packet,
            dump_root=args.dump_root,
            name=name,
            patches=patches,
        )
        results.append(result)
        return result

    try:
        wow64_ps = Path(os.environ.get("WINDIR", r"C:\Windows")) / "SysWOW64" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        if wow64_ps.exists():
            p32 = spawn_hidden([str(wow64_ps), "-NoProfile", "-Command", "Start-Sleep -Seconds 600"])
            spawned.append(p32)
            case("syswow64_powershell32_pid_only", external_patches(p32.pid))
        else:
            print(f"skip syswow64 process: not found at {wow64_ps}")

        current_pid = os.getpid()
        for dll_name in ["kernel32.dll", "kernelbase.dll", "ntdll.dll", "advapi32.dll"]:
            try:
                base, size = load_module_info(dll_name)
            except OSError as exc:
                print(f"skip {dll_name}: {exc}")
                continue
            result = case(
                f"current_process_target_{Path(dll_name).stem}",
                external_patches(current_pid, base, size),
            )
            if result.catalog_valid:
                print(f"catalog branch hit by {dll_name}: {result.catalog_path}")
                break

        private_addr, private_size = allocate_private_exec_region()
        case("private_exec_region_no_mapped_file", external_patches(current_pid, private_addr, private_size))

        case("invalid_pid", external_patches(0x7FFFFFFE))
        case("missing_file_id", local_file_patches(0x1111222233334444, 0x13572468))

        if not args.skip_local_files:
            for name, path in write_test_files(args.dump_root / "inputs").items():
                file_id, serial = file_id_and_volume(path)
                case(f"local_{name}", local_file_patches(file_id, serial))

            system_file = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "kernel32.dll"
            if system_file.exists():
                file_id, serial = file_id_and_volume(system_file)
                case("local_system_kernel32_file_id", local_file_patches(file_id, serial))

    finally:
        for proc in spawned:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()

    print("\n=== summary ===")
    failures = 0
    catalog_hits = 0
    for r in results:
        ok = r.returncode == 0 and r.diff_count == 0
        if not ok:
            failures += 1
        if r.catalog_valid:
            catalog_hits += 1
        print(
            f"{'OK  ' if ok else 'DIFF'} {r.name}: "
            f"diff={r.diff_count} first={r.first_diff} rc={r.returncode} "
            f"catalogValid={r.catalog_valid} wintrust=0x{(r.wintrust_status or 0):08x} "
            f"catalog=0x{(r.catalog_status or 0):08x}"
        )
        if r.mapped_name:
            print(f"     mapped={r.mapped_name}")
        if r.catalog_valid and r.catalog_path:
            print(f"     catalogPath={r.catalog_path}")
        print(f"     dump={r.dump_dir}")

    if catalog_hits == 0:
        print("warning: no catalog-signed branch was observed in this run")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
