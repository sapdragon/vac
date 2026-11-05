#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import secrets
import struct
import sys
from pathlib import Path

SIGNATURE_OFFSET = 0x40
SIGNATURE_BLOCK = 0x90
SIGNATURE_SIZE = 128
SHA1_PREFIX = bytes.fromhex("3021300906052b0e03021a05000414")
RSA_ENCRYPTION = bytes.fromhex("300d06092a864886f70d0101010500")


def is_probable_prime(value: int) -> bool:
    if value < 2 or value % 2 == 0:
        return value == 2
    odd, twos = value - 1, 0
    while odd % 2 == 0:
        odd, twos = odd // 2, twos + 1
    for _ in range(40):
        witness = pow(secrets.randbelow(value - 3) + 2, odd, value)
        if witness in (1, value - 1):
            continue
        for _ in range(twos - 1):
            witness = witness * witness % value
            if witness == value - 1:
                break
        else:
            return False
    return True


def random_prime(bits: int, exponent: int) -> int:
    while True:
        value = secrets.randbits(bits) | (3 << (bits - 2)) | 1
        if value % exponent != 1 and is_probable_prime(value):
            return value


def der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def der(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + der_length(len(body)) + body


def der_int(value: int) -> bytes:
    raw = value.to_bytes((value.bit_length() + 8) // 8, "big")
    return der(2, raw)


def public_key_hex(modulus: int, exponent: int) -> str:
    inner = der(0x30, der_int(modulus) + der_int(exponent))
    return der(0x30, RSA_ENCRYPTION + der(3, b"\0" + inner)).hex().upper()


def keygen(key_path: Path, public_path: Path) -> None:
    exponent = 17
    while True:
        p, q = random_prime(512, exponent), random_prime(512, exponent)
        modulus = p * q
        if modulus.bit_length() == SIGNATURE_SIZE * 8:
            break
    private = pow(exponent, -1, (p - 1) * (q - 1))
    key_path.write_text(json.dumps({"n": hex(modulus), "e": exponent, "d": hex(private)}), encoding="utf-8")
    public_path.write_text(public_key_hex(modulus, exponent), encoding="ascii")


def make_room_for_signature(data: bytearray, pe: int, path: Path) -> int:
    wanted = SIGNATURE_OFFSET + SIGNATURE_BLOCK
    if pe >= wanted:
        return pe

    count, optional_size = struct.unpack_from("<H", data, pe + 6)[0], struct.unpack_from("<H", data, pe + 20)[0]
    size = 24 + optional_size + count * 40
    size_of_headers = struct.unpack_from("<I", data, pe + 24 + 60)[0]
    if wanted + size > size_of_headers:
        raise SystemExit(f"{path}: no room for the signature block")
    headers = bytes(data[pe:pe + size])
    data[pe:pe + size] = bytes(size)
    data[wanted:wanted + size] = headers
    struct.pack_into("<I", data, 0x3C, wanted)
    return wanted


def sign(key_path: Path, input_path: Path, output_path: Path) -> None:
    key = json.loads(key_path.read_text(encoding="utf-8"))
    data = bytearray(input_path.read_bytes())
    pe = make_room_for_signature(data, struct.unpack_from("<I", data, 0x3C)[0], input_path)
    optional = pe + 24
    is_64 = struct.unpack_from("<H", data, optional)[0] == 0x20B
    data[SIGNATURE_OFFSET:SIGNATURE_OFFSET + SIGNATURE_BLOCK] = struct.pack("<4I", 0x564C56, 1, len(data), 0) + bytes(SIGNATURE_SIZE)
    data[optional + 64:optional + 68] = bytes(4)
    security = optional + (144 if is_64 else 128)
    data[security:security + 8] = bytes(8)

    digest = hashlib.sha1(bytes(data)).digest()
    block = b"\0\1" + b"\xff" * (SIGNATURE_SIZE - 3 - len(SHA1_PREFIX) - len(digest)) + b"\0" + SHA1_PREFIX + digest
    signature = pow(int.from_bytes(block, "big"), int(key["d"], 16), int(key["n"], 16))
    data[SIGNATURE_OFFSET + 16:SIGNATURE_OFFSET + 16 + SIGNATURE_SIZE] = signature.to_bytes(SIGNATURE_SIZE, "big")
    output_path.write_bytes(bytes(data))


def main() -> int:
    if len(sys.argv) == 4 and sys.argv[1] == "keygen":
        keygen(Path(sys.argv[2]), Path(sys.argv[3]))
        return 0
    if len(sys.argv) == 5 and sys.argv[1] == "sign":
        sign(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]))
        return 0
    print("usage: sign_module.py keygen <key.json> <public_key.hex>")
    print("       sign_module.py sign <key.json> <input.dll> <output.dll>")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
