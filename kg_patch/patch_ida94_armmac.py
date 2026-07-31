#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IDA 9.4 macOS Apple Silicon patch helper.

The script only accepts the IDA 9.4 ARM64 dylibs identified during the
comparison with the supplied x64 patches.  It replaces the two verified
128-byte public-key constants in each library, preserves the original files,
and can optionally copy/generate the matching license and ad-hoc re-sign the
modified dylibs.

Examples:
  # Produce a separate patched directory (safe default)
  python3 patch_ida94_armmac.py --input-dir /path/to/Contents/MacOS --apply

  # Patch an installed application, retaining .bak backups, then sign it
  python3 patch_ida94_armmac.py \\
      --app "/Applications/IDA Professional 9.4.app" \\
      --in-place --apply --generate-license --sign
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
TARGETS = ("libida.dylib", "libida32.dylib")
EXPECTED_HITS = 2
KEYGEN_NAME = "全平台注册机IDA94b1.py"
LICENSE_NAME = "idapro.hexlic"

# Original key embedded by the unmodified IDA 9.4 ARM64 libraries.
ORIG_KEY = bytes.fromhex(
    "29f4481f796f9f66f2ff13cc4ab5b54f60845db603ba2c0bac8a9bc4b6cbdefc"
    "5c62bfc2f5ee850ac45ea97ad347e8b56dba5085af8c8aad9cc2ec626ca78a06"
    "8006d658f68651da31a0a77c65a70ed73a40d53b08edd403c095aa0bcffa52f3"
    "13ebcacaaa2ce5024a4e2b9aa70fc6092f38ae094d71e43f7690b5ddd3e9e4f7"
)

# Replacement key used by the supplied kg_patch license generator.
PATCH_KEY = bytes.fromhex(
    "a107b71c8a08ba5350934f7cf6e81be3a24dc2e35f7200d80cbd70b37ed6811d"
    "d2146d3cb7e20ad19b2544c0ef14c5c66ffbbdf226ec3f3d544c04385303ca4a"
    "7179299340022f5d50948bcf8a60307e2c196329e51a5296dc419e40fef3ef7c"
    "6f015a09ebd979e79615338985643e666c14897f9f597e11f44341f496d56861"
)

# Informational only. The actual safety check is the byte-pattern hit count.
KNOWN_OFFSETS = {
    "libida.dylib": (0x1C419A0, 0x1C41A48),
    "libida32.dylib": (0x1C28870, 0x1C28918),
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def find_all(data: bytes, needle: bytes) -> list[int]:
    hits: list[int] = []
    start = 0
    while True:
        index = data.find(needle, start)
        if index == -1:
            return hits
        hits.append(index)
        start = index + 1


def fmt_offsets(offsets: list[int] | tuple[int, ...]) -> str:
    return ", ".join(f"0x{x:x}" for x in offsets) or "none"


def is_arm64_macho(data: bytes) -> bool:
    # MH_MAGIC_64 as a little-endian uint32, followed by CPU_TYPE_ARM64.
    return len(data) >= 8 and data[:4] == b"\xcf\xfa\xed\xfe" and data[4:8] == b"\x0c\x00\x00\x01"


def inspect_target(path: Path) -> tuple[bytes, list[int], list[int]]:
    data = path.read_bytes()
    if not is_arm64_macho(data):
        raise RuntimeError(f"{path}: not a thin arm64 Mach-O dylib; refusing to patch")

    original_hits = find_all(data, ORIG_KEY)
    patched_hits = find_all(data, PATCH_KEY)
    print(f"\n== {path} ==")
    print(f"size             : {len(data)}")
    print(f"sha256           : {digest(data)}")
    print(f"original key hits: {fmt_offsets(original_hits)}")
    print(f"patched key hits : {fmt_offsets(patched_hits)}")
    print(f"known IDA 9.4 offs: {fmt_offsets(KNOWN_OFFSETS[path.name])}")
    return data, original_hits, patched_hits


def patch_library(src: Path, dst: Path, apply: bool, in_place: bool) -> bool:
    data, original_hits, patched_hits = inspect_target(src)

    if not original_hits and len(patched_hits) == EXPECTED_HITS:
        print("status           : already patched")
        if apply and not in_place:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            print(f"copied           : {dst}")
        return False

    if len(original_hits) != EXPECTED_HITS or patched_hits:
        raise RuntimeError(
            f"{src}: expected exactly {EXPECTED_HITS} original-key hits and no patched-key "
            "hits. This is not the verified IDA 9.4 ARM64 build; no changes were made."
        )

    patched = data.replace(ORIG_KEY, PATCH_KEY)
    if find_all(patched, ORIG_KEY) or len(find_all(patched, PATCH_KEY)) != EXPECTED_HITS:
        raise RuntimeError(f"{src}: post-patch verification failed")

    print(f"patched sha256   : {digest(patched)}")
    if not apply:
        print("status           : dry-run; add --apply to write files")
        return True

    if in_place:
        backup = src.with_name(src.name + ".bak")
        if not backup.exists():
            shutil.copy2(src, backup)
            print(f"backup           : {backup}")
    else:
        dst.parent.mkdir(parents=True, exist_ok=True)

    dst.write_bytes(patched)
    try:
        shutil.copystat(src, dst)
    except OSError:
        pass
    print(f"written          : {dst}")
    return True


def backup_file_once(path: Path) -> None:
    """Create a sibling .bak file before replacing a user file."""
    if not path.exists():
        return
    backup = path.with_name(path.name + ".bak")
    if not backup.exists():
        shutil.copy2(path, backup)
        print(f"backup           : {backup}")


def generate_license(destination: Path, apply: bool) -> None:
    keygen = SCRIPT_DIR / KEYGEN_NAME
    if not keygen.is_file():
        raise RuntimeError(f"missing bundled license generator: {keygen}")
    if not apply:
        print(f"license          : would generate {destination / LICENSE_NAME}")
        return

    destination.mkdir(parents=True, exist_ok=True)
    target = destination / LICENSE_NAME
    # Generate outside the application bundle first, so an interrupted keygen
    # cannot leave a partially-written license in the destination.
    with tempfile.TemporaryDirectory(prefix="ida94-license-") as tmp:
        tmp_dir = Path(tmp)
        print("license          : generating in a temporary directory")
        subprocess.run([sys.executable, str(keygen)], cwd=tmp_dir, check=True)
        generated = tmp_dir / LICENSE_NAME
        if not generated.is_file() or generated.stat().st_size == 0:
            raise RuntimeError("license generator completed but did not produce idapro.hexlic")
        backup_file_once(target)
        shutil.copy2(generated, target)
    print(f"license written  : {target}")
    print(f"license sha256   : {digest(target.read_bytes())}")


def copy_license(source: Path, destination: Path, apply: bool) -> None:
    if not source.is_file():
        raise RuntimeError(f"license file not found: {source}")
    target = destination / LICENSE_NAME
    if not apply:
        print(f"license          : would copy {source} -> {target}")
        return
    destination.mkdir(parents=True, exist_ok=True)
    if source.resolve() == target.resolve():
        print(f"license          : already at {target}")
        return
    backup_file_once(target)
    shutil.copy2(source, target)
    print(f"license copied   : {target}")


def sign_libraries(directory: Path, apply: bool) -> None:
    if not apply:
        print("codesign         : would ad-hoc sign the two modified dylibs")
        return
    codesign = shutil.which("codesign")
    if not codesign:
        raise RuntimeError("--sign requires macOS codesign; run this step on the Mac")
    for name in TARGETS:
        target = directory / name
        print(f"codesign         : {target}")
        subprocess.run(
            [codesign, "--force", "--sign", "-", "--timestamp=none", str(target)],
            check=True,
        )


def resolve_input(args: argparse.Namespace) -> Path:
    if args.app:
        app = Path(args.app).expanduser()
        macos = app / "Contents" / "MacOS"
        if not macos.is_dir():
            raise RuntimeError(f"not an IDA app bundle (missing Contents/MacOS): {app}")
        return macos
    return Path(args.input_dir).expanduser()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Patch the verified IDA 9.4 macOS ARM64 libida libraries safely."
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--input-dir", default=".", help="directory containing libida.dylib and libida32.dylib")
    source.add_argument("--app", help="IDA application bundle, e.g. /Applications/IDA Professional 9.4.app")
    parser.add_argument("--out-dir", default="mac_arm_patched", help="separate output directory (default: mac_arm_patched)")
    parser.add_argument("--in-place", action="store_true", help="replace source files after creating .bak backups")
    parser.add_argument("--apply", action="store_true", help="write files; otherwise perform only a dry-run")
    license_group = parser.add_mutually_exclusive_group()
    license_group.add_argument("--generate-license", action="store_true", help="run the bundled generator in the destination directory")
    license_group.add_argument("--license", metavar="PATH", help="copy this existing idapro.hexlic into the destination directory")
    parser.add_argument("--use-bundled-license", action="store_true", help="copy kg_patch/idapro.hexlic into the destination directory")
    parser.add_argument("--sign", action="store_true", help="ad-hoc sign modified dylibs with macOS codesign")
    args = parser.parse_args()

    if args.in_place and not args.apply:
        parser.error("--in-place requires --apply")
    if args.sign and not args.apply:
        parser.error("--sign requires --apply")
    if args.generate_license and args.use_bundled_license:
        parser.error("--generate-license and --use-bundled-license cannot be used together")
    if args.license and args.use_bundled_license:
        parser.error("--license and --use-bundled-license cannot be used together")

    try:
        source_dir = resolve_input(args).resolve()
        if not source_dir.is_dir():
            raise RuntimeError(f"input directory not found: {source_dir}")
        output_dir = source_dir if args.in_place else Path(args.out_dir).expanduser().resolve()
        if not args.in_place and output_dir == source_dir:
            raise RuntimeError("output directory equals input directory; use --in-place explicitly")

        changed = False
        for name in TARGETS:
            src = source_dir / name
            if not src.is_file():
                raise RuntimeError(f"missing target: {src}")
            dst = src if args.in_place else output_dir / name
            changed |= patch_library(src, dst, args.apply, args.in_place)

        if args.generate_license:
            generate_license(output_dir, args.apply)
        elif args.license:
            copy_license(Path(args.license).expanduser(), output_dir, args.apply)
        elif args.use_bundled_license:
            copy_license(SCRIPT_DIR / LICENSE_NAME, output_dir, args.apply)

        if args.sign:
            sign_libraries(output_dir, args.apply)

        print("\nDone.")
        if args.apply and changed and not args.sign:
            print("Next on macOS: rerun with --sign, or execute:")
            print(f"  codesign --force --sign - --timestamp=none {output_dir / 'libida.dylib'}")
            print(f"  codesign --force --sign - --timestamp=none {output_dir / 'libida32.dylib'}")
        return 0
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
