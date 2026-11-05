# vac

Byte-for-byte C++20 reconstruction of 15 classic x86 Valve Anti-Cheat (VAC) scan modules and `steamservice.dll`.

Every rebuilt worker is verified against the original signed Valve binaries (`../vac-research`) for exact 4232-byte output parity, including original quirks, uninitialized stack garbage, and bugs marked with `// valve bug, keep it`.

## Writeup

Full technical breakdown of `steamservice.dll`, the shared module SDK, all 15 scanners, and Valve's bugs:

- **English:** [WRITEUP.en.md](docs/writeup/WRITEUP.en.md) ([PDF](docs/writeup/WRITEUP.en.pdf))
- **Russian:** [WRITEUP.ru.md](docs/writeup/WRITEUP.ru.md) ([PDF](docs/writeup/WRITEUP.ru.pdf))

## Repository layout

| Path | Description |
|---|---|
| `sdk/` | Shared module runtime: `_runfunc@20`, `.vacini`, `RunDispatcher`, `BootstrapMain` (172 imports), ICE, raw RSA-512, MD5/CRC32, LZ4, PE/NT helpers |
| `modules/` | 15 reconstructed scan modules (one directory per module) |
| `service/` | Reconstruction of `steamservice.dll`: IPC module manager, `VLV` RSA-1024 signature check, manual mapper (`LoadModuleHiddenInternal`), and 5-minute ETW process monitor |
| `tests/` | Live and synthetic byte-for-byte parity suites against the original DLLs |
| `tools/` | Module blob generators, worker node inspector, IDA export and `@orig` verification scripts |

## Reconstructed modules

| Module | Worker IDs | Summary |
|---|---|---|
| `boot_config` | `0x06A79A9E` | BCD registry hive (`HKLM\BCD00000000\Objects`), `testsigning` / `nointegritychecks`, NX policy, NTFS File ID |
| `cpuid` | `0x023429C3` | CPU 0 affinity pin and `CPUID` leaf dump (`0x0`, `0x40000000`, `0x80000000`) |
| `devices` | `0x05EC50DC` | Active PCI and USB device enumeration via SetupAPI |
| `driver_inventory` | `0x06ACD913`, `0x06C2B5BB` | Active driver services vs `\Driver` object directory + normalized MD5 of driver files |
| `image_scan` | `0x0CDA6778`, `0x09D3248C` | Disk/memory PE scanner (relocation-stripped MD5, icons, PDB, WinTrust, pattern scan) + thread start addresses |
| `image_scan_threads` | `0x05A52008`, `0x0122C7DA` | Same `.text` as `image_scan` built with rotated keys and worker IDs |
| `payload_executor` | `0x0236ED5F` | Memory allocation, RSA payload unpacker, `PAGE_EXECUTE_READWRITE`, and entry call |
| `process_file_identity` | `0x0B2D8276`, `0x0CA11165`, `0x013B4330` | Process dossier (SID, PEB32/64, cmdline, hashes), ancestor NTFS File ID chain, directory inventory |
| `process_memory_map` | `0x06E048F4`, `0x0DB55D3C` | `PEB->Ldr` and virtual memory walk, page folding, relocation-stripped PE MD5, LZ4 report tail |
| `service_lookup` | `0x0FA94991` | Driver lookup by service name hash, `sysnative` expansion, NTFS File ID |
| `shared_section` | `0x0E3481C0`, `0x06781BC4` | Named section lookup by GUID pattern via `OpenFileMappingW` and NT `\` directory walk |
| `system_handles` | `0x002F6DC7`, `0x0929BC41` | Toolhelp snapshot, 64-bit handle type masks, and hidden PID brute-force (`unPid -= 4`) |
| `system_info` | `0x0F8083A0`, `0x0C2232C2` | OS summary, `KUSER_SHARED_DATA`, volumes, and on-disk `ntdll.dll` export parser for raw SSNs |
| `target_handles` | `0x08A9324E` | WoW64 Heaven's Gate (`0x33`) direct x64 syscalls hunting processes with handles to the game |
| `timing_check` | `0x0D8C40E1` | Legacy module without `BootstrapMain`: `KUSER_SHARED_DATA` ticks around a patched `.data` stub |

## Build and test

Open `vac.sln` in Visual Studio 2022 (`Release | Win32`), or build and run the full parity suite from the command line:

```powershell
python tests/build_tests.py
python tests/parity/run_all.py
python tools/ida/fill_orig.py --check sdk modules service
```

`run_all.py` runs each worker live against the original DLLs (filtering out OS noise by running the original binary twice against itself first), verifies full `_runfunc@20` output packets including ICE and RSA-512 sealing, and executes the deterministic fuzz/synthetic suites.
