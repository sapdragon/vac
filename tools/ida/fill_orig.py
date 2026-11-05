#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EXPORT = ROOT / "analysis" / "export"
TOKEN = re.compile(r"(//\s*@orig:\s*)([0-9a-f]{6,8}):([^\s]+)\s*$", re.M)
FILLED = re.compile(r"//\s*@orig:\s*((?:[0-9A-F]{2}|\?)(?: (?:[0-9A-F]{2}|\?))*)\s*$", re.M)
BINARY = re.compile(r"//\s*@binary:\s*([0-9a-f]{6,8})")
NO_SIGNATURE = "no unique signature"


def load(crc: str, cache: dict) -> list[dict]:
    if crc not in cache:
        path = EXPORT / crc / "funcs.json"
        cache[crc] = json.loads(path.read_text(encoding="utf-8"))["funcs"] if path.exists() else None
    return cache[crc]


def resolve(funcs: list[dict], reference: str) -> dict | None:
    if reference.lower().startswith("0x"):
        ea = int(reference, 16)
        return next((f for f in funcs if int(f["ea"], 16) == ea), None)
    return next((f for f in funcs if f["name"] == reference), None)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("paths", nargs="+")
    args = ap.parse_args()

    cache: dict = {}
    errors, filled, verified = [], 0, 0
    files = [f for p in args.paths for f in Path(p).rglob("*") if f.suffix in (".cpp", ".hpp", ".inl")]
    for path in files:
        text = path.read_text(encoding="utf-8")
        binary = BINARY.search(text)

        def replace(match: re.Match) -> str:
            nonlocal filled
            prefix, crc, reference = match.groups()
            funcs = load(crc, cache)
            if funcs is None:
                errors.append(f"{path}: no export for {crc}")
                return match.group(0)
            func = resolve(funcs, reference)
            if func is None:
                errors.append(f"{path}: {crc} has no function {reference}")
                return match.group(0)
            filled += 1
            return f"{prefix}{func['sig']}" if func["sig"] else f"{prefix}{crc}:{func['ea']} ({NO_SIGNATURE})"

        new_text = TOKEN.sub(replace, text)
        if args.check and new_text != text:
            errors.append(f"{path}: has unfilled @orig tags")
        if not args.check and new_text != text:
            path.write_text(new_text, encoding="utf-8", newline="")

        for match in FILLED.finditer(new_text):
            funcs = load(binary.group(1), cache) if binary else None
            if funcs is None:
                errors.append(f"{path}: filled @orig without a usable @binary line")
            elif not any(f["sig"] == match.group(1) for f in funcs):
                errors.append(f"{path}: signature not in export: {match.group(1)}")
            else:
                verified += 1

    print(f"filled={filled} verified={verified} errors={len(errors)}")
    for error in errors:
        print(error)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
