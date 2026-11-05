#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import random
import struct
import zlib
from pathlib import Path

OUT = Path(__file__).with_name("known_answers.inl")
ROOT = Path(__file__).resolve().parents[2]


def array(name: str, data: bytes) -> str:
    rows = [", ".join(f"0x{b:02X}" for b in data[i : i + 16]) for i in range(0, len(data), 16)]
    body = ",\n\t".join(rows) if rows else "0"
    return f"inline const unsigned char {name}[] = {{\n\t{body}\n}};\n"


def u32_array(name: str, values: list[int]) -> str:
    body = ", ".join(f"0x{v & 0xFFFFFFFF:08X}u" for v in values)
    return f"inline const unsigned int {name}[] = {{ {body} }};\n"


SMOD = [[333, 313, 505, 369], [379, 375, 319, 391], [361, 445, 451, 397], [397, 425, 395, 505]]
SXOR = [[0x83, 0x85, 0x9B, 0xCD], [0xCC, 0xA7, 0xAD, 0x41], [0x4B, 0x2E, 0xD4, 0x33], [0xEA, 0xCB, 0x2E, 0x04]]
PBOX = [
    0x00000001, 0x00000080, 0x00000400, 0x00002000, 0x00080000, 0x00200000, 0x01000000, 0x40000000,
    0x00000008, 0x00000020, 0x00000100, 0x00004000, 0x00010000, 0x00800000, 0x04000000, 0x20000000,
    0x00000004, 0x00000010, 0x00000200, 0x00008000, 0x00020000, 0x00400000, 0x08000000, 0x10000000,
    0x00000002, 0x00000040, 0x00000800, 0x00001000, 0x00040000, 0x00100000, 0x02000000, 0x80000000,
]
KEYROT = [0, 1, 2, 3, 2, 1, 3, 0, 1, 3, 2, 0, 3, 1, 0, 2]


def gf_mult(a: int, b: int, m: int) -> int:
    res = 0
    while b:
        if b & 1:
            res ^= a
        a <<= 1
        b >>= 1
        if a >= 256:
            a ^= m
    return res


def gf_exp7(b: int, m: int) -> int:
    if b == 0:
        return 0
    x = gf_mult(b, b, m)
    x = gf_mult(b, x, m)
    x = gf_mult(x, x, m)
    return gf_mult(b, x, m)


def perm32(x: int) -> int:
    res, i = 0, 0
    while x:
        if x & 1:
            res |= PBOX[i]
        i += 1
        x >>= 1
    return res


SBOX = [[0] * 1024 for _ in range(4)]
for i in range(1024):
    col, row = (i >> 1) & 0xFF, (i & 1) | ((i & 0x200) >> 8)
    for box, shift in enumerate((24, 16, 8, 0)):
        SBOX[box][i] = perm32(gf_exp7(col ^ SXOR[box][row], SMOD[box][row]) << shift)


def ice_schedule(key: bytes) -> list[list[int]]:
    sched = [[0, 0, 0] for _ in range(16)]
    kb = [0] * 4
    for j in range(4):
        kb[3 - j] = (key[j * 2] << 8) | key[j * 2 + 1]
    for n, rot in ((0, KEYROT[0:8]), (8, KEYROT[8:16])):
        for i in range(8):
            isk = sched[n + i]
            for j in range(15):
                for k in range(4):
                    idx = (rot[i] + k) & 3
                    bit = kb[idx] & 1
                    isk[j % 3] = ((isk[j % 3] << 1) | bit) & 0xFFFFFFFF
                    kb[idx] = (kb[idx] >> 1) | ((bit ^ 1) << 15)
    return sched


def ice_f(p: int, sk: list[int]) -> int:
    tl = ((p >> 16) & 0x3FF) | (((p >> 14) | (p << 18)) & 0xFFC00)
    tr = (p & 0x3FF) | ((p << 2) & 0xFFC00)
    al = sk[2] & (tl ^ tr)
    ar = al ^ tr
    al ^= tl
    al ^= sk[0]
    ar ^= sk[1]
    return SBOX[0][al >> 10] | SBOX[1][al & 0x3FF] | SBOX[2][ar >> 10] | SBOX[3][ar & 0x3FF]


def ice_encrypt(key: bytes, block: bytes) -> bytes:
    sched = ice_schedule(key)
    left, right = struct.unpack(">II", block)
    for i in range(0, 16, 2):
        left ^= ice_f(right, sched[i])
        right ^= ice_f(left, sched[i + 1])
    return struct.pack(">II", right, left)


assert ice_encrypt(bytes.fromhex("deadbeef01234567"), bytes.fromhex("fedcba9876543210")) == bytes.fromhex(
    "7d6ef1ef30d47a96"
), "the ICE vector from Kwan's paper"


def to_i32(v: int) -> int:
    v &= 0xFFFFFFFF
    return v - (1 << 32) if v & 0x80000000 else v


class ParkMiller:
    def __init__(self, seed: int):
        self.state, self.out, self.shuffle = to_i32(seed), 0, [0] * 32

    def step(self, x: int) -> int:
        v = to_i32(16807 * x - 0x7FFFFFFF * (x // 127773))
        return v + 0x7FFFFFFF if v < 0 else v

    def next(self) -> int:
        x = self.state
        if x <= 0 or self.out == 0:
            x = to_i32(-x)
            if x < 1:
                x = 1
            for i in range(39, -1, -1):
                x = self.step(x)
                if i < 32:
                    self.shuffle[i] = x
            self.out = self.shuffle[0]
        x = self.step(x)
        bucket = self.out // 0x4000000
        self.out = self.shuffle[bucket]
        self.shuffle[bucket] = x
        self.state = x
        return self.out


def hash_488781ed(data: bytes, seed: int = 0) -> int:
    h = seed
    for b in data:
        h ^= b << 24
        for _ in range(8):
            h = ((h << 1) ^ 0x488781ED) & 0xFFFFFFFF if h & 0x80000000 else (h << 1) & 0xFFFFFFFF
    return h


def name_hash(data: bytes) -> int:
    h = 0x45D71892
    for b in data:
        h = ((b | 0x20) + 33 * h) & 0xFFFFFFFF
    return h


def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def der(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + der_len(len(body)) + body


def der_int(v: int) -> bytes:
    raw = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
    if raw[0] & 0x80:
        raw = b"\0" + raw
    return der(2, raw)


ALG_ID = bytes.fromhex("300d06092a864886f70d0101010500")


def spki(n: int, e: int) -> bytes:
    inner = der(0x30, der_int(n) + der_int(e))
    return der(0x30, ALG_ID + der(3, b"\0" + inner))


def real_module_key() -> bytes:
    text = (ROOT / "modules" / "shared_section" / "internal" / "module_data.inl").read_text(encoding="utf-8")
    block = text[text.index("k_rgubRsaPublicKey") : text.index("};")]
    block = block[block.index("{") + 1 :]
    return bytes(int(t.strip(), 16) for t in block.split(",") if t.strip())


def parse_spki(key: bytes) -> tuple[int, int]:
    def tlv(data: bytes, off: int) -> tuple[int, int, int]:
        tag, length, pos = data[off], data[off + 1], off + 2
        if length & 0x80:
            count = length & 0x7F
            length = int.from_bytes(data[pos : pos + count], "big")
            pos += count
        return tag, pos, length

    _, pos, _ = tlv(key, 0)
    pos += len(ALG_ID)
    _, pos, _ = tlv(key, pos)
    pos += 1
    _, pos, _ = tlv(key, pos)
    _, npos, nlen = tlv(key, pos)
    n = int.from_bytes(key[npos : npos + nlen], "big")
    _, epos, elen = tlv(key, npos + nlen)
    return n, int.from_bytes(key[epos : epos + elen], "big")


IMAGE_BASE32 = 0x10400000
SECTION_ALIGN, FILE_ALIGN = 0x1000, 0x200
EXEC, READ, DATA = 0x20000000, 0x40000000, 0x40


def section(name: bytes, vsize: int, va: int, raw: int, ptr: int, chars: int) -> bytes:
    return struct.pack("<8sIIIIIIHHI", name.ljust(8, b"\0"), vsize, va, raw, ptr, 0, 0, 0, 0, chars)


def build_pe(
    pe64: bool,
    sections: list[tuple[bytes, int, int, bytes, int]],
    dirs: dict[int, tuple[int, int]],
    overlay: bytes = b"",
    checksum: int = 0x11223344,
) -> bytes:
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    opt_size = 0xF0 if pe64 else 0xE0
    file_header = struct.pack(
        "<HHIIIHH", 0x8664 if pe64 else 0x14C, len(sections), 0x5F000000, 0, 0, opt_size, 0x2102
    )
    directories = b"".join(struct.pack("<II", *dirs.get(i, (0, 0))) for i in range(16))
    if pe64:
        opt = struct.pack("<HBBIIIII", 0x20B, 14, 0, 0x200, 0x200, 0, 0x1000, 0x1000)
        opt += struct.pack("<QII", 0x180000000, SECTION_ALIGN, FILE_ALIGN)
    else:
        opt = struct.pack("<HBBIIIIII", 0x10B, 14, 0, 0x200, 0x200, 0, 0x1000, 0x1000, 0x2000)
        opt += struct.pack("<III", IMAGE_BASE32, SECTION_ALIGN, FILE_ALIGN)
    opt += struct.pack("<HHHHHHI", 6, 0, 0, 0, 6, 0, 0)
    opt += struct.pack("<III", 0x8000, 0x400, checksum)
    opt += struct.pack("<HH", 2, 0x8140)
    opt += struct.pack("<QQQQ", 0x100000, 0x1000, 0x100000, 0x1000) if pe64 else struct.pack(
        "<IIII", 0x100000, 0x1000, 0x100000, 0x1000
    )
    opt += struct.pack("<II", 0, 16) + directories
    assert len(opt) == opt_size, len(opt)

    headers = bytes(dos) + b"PE\0\0" + file_header + opt
    first_raw = 0x400
    assert len(headers) + 40 * len(sections) <= first_raw
    table, body, ptr = b"", b"", first_raw
    for name, vsize, va, raw, chars in sections:
        table += section(name, vsize, va, len(raw), ptr if raw else 0, chars)
        body += raw
        ptr += len(raw)
    return (headers + table).ljust(first_raw, b"\0") + body + overlay


def normalized_digest(image: bytes, loaded_base: int, append_overlay: bool) -> bytes | None:
    nt = struct.unpack_from("<I", image, 0x3C)[0]
    machine, nsec, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", image, nt + 4)
    opt_off = nt + 24
    opt = bytearray(image[opt_off : opt_off + opt_size])
    pe64 = opt_size == 0xF0
    if pe64:
        opt[0x18:0x20] = bytes(8)
        dirs_off = 0x70
        image_base = 0
    else:
        image_base = loaded_base or struct.unpack_from("<I", opt, 0x1C)[0]
        opt[0x1C:0x20] = bytes(4)
        dirs_off = 0x60
    alignment = struct.unpack_from("<I", opt, 0x20)[0]

    def directory(i: int) -> tuple[int, int]:
        return struct.unpack_from("<II", opt, dirs_off + 8 * i)

    sections = []
    for i in range(nsec):
        off = opt_off + opt_size + 40 * i
        name = image[off : off + 8]
        vsize, va, raw, ptr = struct.unpack_from("<IIII", image, off + 8)
        chars = struct.unpack_from("<I", image, off + 36)[0]
        sections.append({"name": name, "vsize": vsize, "va": va, "raw": raw, "ptr": ptr, "chars": chars})

    all_sections = list(sections)
    if append_overlay:
        raw_end = max(s["ptr"] + s["raw"] for s in sections)
        if raw_end < len(image):
            last = sections[-1]
            span = last["vsize"]
            if span < last["raw"]:
                span = last["raw"] + alignment - 1 - (last["raw"] + alignment - 1) % alignment
            va = last["va"] + span + alignment - 1
            va -= va % alignment
            size = len(image) - raw_end
            all_sections.append(
                {
                    "name": b".extra\0\0",
                    "vsize": (size + alignment - 1) - (size + alignment - 1) % alignment,
                    "va": va,
                    "raw": size,
                    "ptr": raw_end,
                    "chars": 0x02000000,
                }
            )

    selected, largest, found_text = None, 0, False
    for s in all_sections:
        executable = bool(s["chars"] & EXEC)
        if s["name"][:5] == b".text" and executable:
            selected, found_text = s, True
        if not found_text and executable and s["raw"] > largest:
            selected, largest = s, s["raw"]
    if selected is None:
        return None

    md5 = hashlib.md5()
    md5.update(image[:0x40])
    md5.update(image[nt + 4 : nt + 24])
    md5.update(bytes(opt))
    for s in sections:
        md5.update(s["name"])
        md5.update(struct.pack("<I", s["va"]))
        md5.update(struct.pack("<I", s["raw"]))

    def split(dir_va: int, dir_size: int, start: int, end: int) -> tuple[list[int], list[int]]:
        cut_start = max(dir_va, start)
        total = (dir_va + dir_size + 4) & 0xFFFFFFFF
        cut_end = total if total < end else end
        if cut_start >= cut_end:
            return [start, 0], [end, 0]
        s2, e2 = (cut_end, end) if cut_end < end else (0, 0)
        if cut_start <= start:
            return [s2, 0], [e2, 0]
        return [start, s2], [cut_start, e2]

    start, end = selected["va"], selected["va"] + selected["raw"]
    iat_s, iat_e = split(*directory(12), start, end)
    exp1_s, exp1_e = split(*directory(0), iat_s[0], iat_e[0])
    exp2_s, exp2_e = split(*directory(0), iat_s[1], iat_e[1])

    def relocate(chunk: bytearray, chunk_rva: int) -> None:
        reloc_va, reloc_size = directory(5)
        if pe64 or not reloc_va or reloc_size < 8 or not image_base:
            return
        for s in all_sections:
            span = max(s["vsize"], s["raw"])
            if s["va"] <= reloc_va < s["va"] + span:
                file_off = s["ptr"] + reloc_va - s["va"]
                break
        else:
            return
        if file_off >= len(image):
            return
        delta = (image_base - 0x10000000) & 0xFFFFFFFF
        size = min(reloc_size, len(image) - file_off)
        cursor = 0
        chunk_end = chunk_rva + len(chunk)
        while cursor + 8 <= size:
            page, block = struct.unpack_from("<II", image, file_off + cursor)
            if block < 8 or cursor + block > size:
                raise ValueError("corrupt")
            if page + 0x1000 > chunk_rva and page < chunk_end:
                for i in range((block - 8) // 2):
                    entry = struct.unpack_from("<H", image, file_off + cursor + 8 + i * 2)[0]
                    if entry >> 12 != 3:
                        continue
                    patch = page + (entry & 0xFFF)
                    if patch < chunk_rva or patch + 4 > chunk_end:
                        continue
                    value = struct.unpack_from("<I", chunk, patch - chunk_rva)[0]
                    struct.pack_into("<I", chunk, patch - chunk_rva, (value - delta) & 0xFFFFFFFF)
            cursor += block

    for a, b in zip(exp1_s + exp2_s, exp1_e + exp2_e):
        rva = a
        while rva < b:
            n = min(b - rva, 4096)
            off = selected["ptr"] + rva - selected["va"]
            chunk = bytearray(image[off : off + n])
            relocate(chunk, rva)
            md5.update(bytes(chunk))
            rva += n
    return md5.digest()


def pe_cases() -> list[tuple[str, bytes, list[tuple[int, bool]]]]:
    code = bytes((i * 7 + 3) & 0xFF for i in range(0x1400))
    relocs = struct.pack("<II", 0x1000, 8 + 4 * 2) + struct.pack(
        "<HHHH", 0x3000 | 0x010, 0x3000 | 0xFFE, 0x0000, 0xA000 | 0x020
    )
    relocs += struct.pack("<II", 0x2000, 8 + 2 * 2) + struct.pack("<HH", 0x3000 | 0x040, 0)
    reloc_size = len(relocs)
    relocs = relocs.ljust(0x200, b"\0")
    data = bytes(range(256)) * 2
    dirs32 = {12: (0x1100, 0x20), 0: (0x1800, 0x10), 5: (0x4000, reloc_size)}

    pe32 = build_pe(
        False,
        [(b".text", 0x1400, 0x1000, code, EXEC | READ), (b".data", 0x200, 0x3000, data, READ | DATA),
         (b".reloc", 0x200, 0x4000, relocs, READ)],
        dirs32,
        overlay=b"OVERLAY-OVERLAY!",
    )

    pe32_overlay_reloc = build_pe(
        False,
        [(b".text", 0x1400, 0x1000, code, EXEC | READ), (b".data", 0x200, 0x3000, data, READ | DATA)],
        {12: (0x1100, 0x20), 0: (0x1800, 0x10), 5: (0x4000, reloc_size)},
        overlay=relocs,
    )

    pe64 = build_pe(
        True,
        [(b".text", 0x1400, 0x1000, code, EXEC | READ), (b".data", 0x200, 0x3000, data, READ | DATA)],
        {12: (0x1200, 0x10), 0: (0x1000, 0x18)},
    )

    pe32_largest = build_pe(
        False,
        [(b".text", 0x200, 0x1000, data, READ), (b"CODE1", 0x200, 0x2000, data, EXEC | READ),
         (b"CODE2", 0x1400, 0x3000, code, EXEC | READ)],
        {},
    )

    return [
        ("Pe32", pe32, [(0, False), (0, True), (0x20000000, False)]),
        ("Pe32OverlayReloc", pe32_overlay_reloc, [(0, False), (0, True)]),
        ("Pe64", pe64, [(0, False), (0, True)]),
        ("Pe32Largest", pe32_largest, [(0, False)]),
    ]


def main() -> None:
    rng = random.Random(0x5AC)
    out = ["// Generated by tests/sdk/known_answers.py. Do not edit.\n// clang-format off\n"]

    vectors = [(bytes.fromhex("deadbeef01234567"), bytes.fromhex("fedcba9876543210"))]
    vectors += [(rng.randbytes(8), rng.randbytes(8)) for _ in range(15)]
    rows = [key + plain + ice_encrypt(key, plain) for key, plain in vectors]
    out.append(array("k_rgubIceVectors", b"".join(rows)))
    out.append(f"inline constexpr unsigned k_cIceVectors = {len(rows)};\n")

    inputs = [b"", b"a", b"abc", b"123456789", b"message digest", bytes(range(256)) * 5 + b"tail"]
    for i, data in enumerate(inputs):
        out.append(array(f"k_rgubHashInput{i}", data))
    out.append(f"inline constexpr unsigned k_cHashInputs = {len(inputs)};\n")
    out.append(
        "#define VAC_TEST_HASH_INPUTS "
        + ", ".join(f"{{ k_rgubHashInput{i}, {len(d)}u }}" for i, d in enumerate(inputs))
        + "\n"
    )
    out.append(u32_array("k_rgunCrc32", [zlib.crc32(d) for d in inputs]))
    out.append(array("k_rgubMd5", b"".join(hashlib.md5(d).digest() for d in inputs)))
    out.append(u32_array("k_rgunHash488781ED", [hash_488781ed(d) for d in inputs]))
    out.append(u32_array("k_rgunHash488781EDSeeded", [hash_488781ed(d, 0xCAFEBABE) for d in inputs]))
    out.append(u32_array("k_rgunPathHash", [name_hash(d) for d in inputs]))

    seeds = [0, 0xFFFFFFFF, 0xFFFFFFFB, 5, 0x80000000, 0x87654321, 0x7FFFFFFF]
    out.append(u32_array("k_rgunParkMillerSeeds", seeds))
    rows = []
    for seed in seeds:
        prng = ParkMiller(seed)
        rows += [prng.next() for _ in range(40)]
    out.append(u32_array("k_rgunParkMillerOutputs", rows))
    out.append("inline constexpr unsigned k_cParkMillerOutputs = 40;\n")

    out.append("inline constexpr unsigned k_nRsaSmallResult = " + str(pow(65, 17, 3233)) + "u;\n")
    n1024 = rng.getrandbits(1024) | (1 << 1023) | 1
    n2048 = rng.getrandbits(2048) | (1 << 2047) | 1
    base1024 = rng.getrandbits(1000)
    big = rng.getrandbits(2200)
    for name, value in (("N1024", n1024), ("N2048", n2048), ("Base1024", base1024), ("Big", big)):
        out.append(array(f"k_rgubRsa{name}", value.to_bytes((value.bit_length() + 7) // 8, "big")))
    out.append(array("k_rgubRsaPow1024", pow(base1024, 65537, n1024).to_bytes(128, "big")))
    out.append(array("k_rgubRsaPow2048", pow(base1024, 65537, n2048).to_bytes(256, "big")))
    out.append(array("k_rgubRsaPowBig", pow(big, 3, n1024).to_bytes(128, "big")))
    out.append(array("k_rgubRsaProduct", (n1024 * n2048).to_bytes((n1024 * n2048).bit_length() // 8 + 1, "big")))
    quotient, remainder = divmod(n2048, n1024)
    out.append(array("k_rgubRsaQuotient", quotient.to_bytes((quotient.bit_length() + 7) // 8, "big")))
    out.append(array("k_rgubRsaRemainder", remainder.to_bytes((remainder.bit_length() + 7) // 8, "big")))

    session = bytes(range(0x40, 0x40 + 28))
    out.append(array("k_rgubRsaSession", session))
    module_key = real_module_key()
    n, e = parse_spki(module_key)
    assert n.bit_length() == 512 and e == 65537
    out.append(array("k_rgubRsaModuleKey", module_key))
    out.append(array("k_rgubRsaModuleCipher", pow(int.from_bytes(session, "big"), e, n).to_bytes(64, "big")))
    out.append(array("k_rgubRsaKey1024", spki(n1024, 65537)))
    out.append(
        array("k_rgubRsaCipher1024", pow(int.from_bytes(session, "big"), 65537, n1024).to_bytes(128, "big"))
    )
    out.append(array("k_rgubRsaKeyTooBig", spki((1 << 8199) | 1, 3)))

    text = b"kernel32.dll"
    out.append(array("k_rgubXorKernel32", bytes(b ^ 0x13 for b in text) + b"\0"))
    out.append(f"inline constexpr unsigned k_unXorWideFirst = 0x{ord('D') ^ 0x13:04X}u;\n")
    out.append(f"inline constexpr unsigned k_unHashKernel32 = 0x{name_hash(text):08X}u;\n")

    for name, image, params in pe_cases():
        out.append(array(f"k_rgub{name}", image))
        digests = b""
        for base, overlay in params:
            digests += normalized_digest(image, base, overlay)
        out.append(array(f"k_rgub{name}Digests", digests))
        out.append(
            f"inline const NormalizedParams_t k_rg{name}Params[] = {{ "
            + ", ".join(f"{{ 0x{b:08X}u, {'true' if o else 'false'} }}" for b, o in params)
            + " };\n"
        )

    out.append("// clang-format on\n")
    OUT.write_text("".join(out), encoding="utf-8", newline="\n")
    print(f"wrote {OUT} ({OUT.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
