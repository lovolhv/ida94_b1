#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IDA Pro 9.4 license keygen (cross-platform Python port of keygen.js).

This ONLY generates the `idapro.hexlic` license file (the "keygen" part).
It does NOT patch any binaries.

Faithful reimplementation of the original keygen.js signing logic:
  * canonical (recursively key-sorted, compact) JSON serialization
  * SHA-256 over {"payload": ...}
  * custom EMSA-style padding (hash placed at offset 95 in a 127-byte block,
    XORed with a fixed 127-byte pad key)
  * raw RSA private-key operation  sig = m^d mod N  (1024-bit)

Integer conventions copied exactly from keygen.js:
  * modulus N and private exponent d : little-endian byte order
  * message block read as            : big-endian integer
  * signature output bytes           : little-endian, padded to 128 bytes
"""

import hashlib
import json

# --- Embedded RSA key material (recovered private key) ----------------------
C_MODULUS = bytes.fromhex(
    "3f0307607fed562fd5a163adc40fcc603373caa28414e64cdc4552a555b13ad4"
    "b3ad0a812800a03195300fd71634b90edb0d69ea710efebb2b0b9e72da2effb1"
    "49de70bcbfa94b86af01ce455dbbd5fa987207651c7b60c2e4cafd0654188d98"
    "c30f64dc084d8547f0ac32db91124af82b3b15bf922a31f1d5e332f27615cea7"
)
PRIVATE_KEY = bytes.fromhex(
    "8b3f5fdfad7f87239734c530e2ecebeb4fa48d79518756c15fd54636801cf7ea"
    "6367100566bf8b52b16bec05258d8426ea94c15841ab2d37802c07349df4c208"
    "584e86d25a6bfb82966cb2ddcd3d654e9994e814ca470577362a937cc984e404"
    "a0b68d173aab3180130118e1b03ed209a9d8757560a85a3c9b0d3380e7907c4f"
)

V54 = 127   # block length
V56 = 95    # offset where the 32-byte hash is placed (95 + 32 == 127)
PADKEY = bytes.fromhex(
    "e2a7c300dfcc777f89b57500d8151c7fb1d97b3f9f170393311234ceeb9e377a"
    "e2a7c300dfcc777f89b57500d8151c7fb1d97b3f9f170393311234ceeb9e377a"
    "e2a7c300dfcc777f89b57500d8151c7fb1d97b3f9f170393311234ceeb9e377a"
    "e2a7c300dfcc777f89b57500d8151c7fb1d97b3f9f170393311234ceeb9e37"
)


# --- License definition (mirrors keygen.js) ---------------------------------
def build_license():
    license = {
        "header": {"version": 1},
        "payload": {
            "name": "yigod",
            "email": "Henglie@vip.qq.com",
            "licenses": [
                {
                    "description": "license",
                    "edition_id": "ida-pro",
                    "id": "14-0000-FFFF-88",
                    "license_type": "named",
                    "product": "IDA",
                    "seats": 1,
                    "start_date": "2024-08-10 00:00:00",
                    "end_date": "2099-12-31 23:59:59",
                    "issued_on": "2025-07-20 00:00:00",
                    "owner": "yigod",
                    "product_id": "IDAPRO",
                    "product_version": "9.4",
                    "add_ons": [],
                    "features": [],
                }
            ],
        },
    }
    add_addons(license)
    return license


def add_addons(license):
    addons = [  # update as needed, doesn't include cloud add-ons
        "LUMINA", "TEAMS",
        "HEXX86", "HEXX64", "HEXARM", "HEXARM64",
        "HEXMIPS", "HEXMIPS64", "HEXPPC", "HEXPPC64",
        "HEXRV", "HEXRV64", "HEXARC", "HEXARC64",
        "HEXV850", "HEXDALVIK",
    ]
    lic0 = license["payload"]["licenses"][0]
    for i, addon in enumerate(addons):
        lic0["add_ons"].append({
            "id": "48-1337-B00B-%02d" % (i + 1),
            "code": addon,
            "owner": lic0["id"],
            "start_date": "2025-07-20 00:00:00",
            "end_date": "2099-12-31 23:59:59",
        })


# --- Helper functions -------------------------------------------------------
def canonical(obj):
    """Recursive key-sorted, compact JSON string (matches JS `sort()`)."""
    if isinstance(obj, list):
        return "[" + ",".join(canonical(x) for x in obj) + "]"
    if isinstance(obj, dict):
        keys = sorted(obj.keys())
        return "{" + ",".join('"' + k + '":' + canonical(obj[k]) for k in keys) + "}"
    # primitive: bool/int/float/str/None -> same textual form as JSON.stringify
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def encrypt(message: bytes) -> bytes:
    """Raw RSA private operation, replicating keygen.js integer conventions."""
    modulus = int.from_bytes(C_MODULUS, "little")
    key = int.from_bytes(PRIVATE_KEY, "little")
    msg = int.from_bytes(message, "big")  # == little-endian of reversed(message)

    base = msg % modulus
    encrypted = pow(base, key, modulus)

    # output little-endian, trimmed of high zero bytes (JS pushes LSB first)
    length = (encrypted.bit_length() + 7) // 8
    return encrypted.to_bytes(length, "little")


def sign(payload) -> str:
    data_str = canonical({"payload": payload})
    digest = hashlib.sha256(data_str.encode("utf-8")).digest()  # 32 bytes

    U = bytearray(V54)
    U[V56:V56 + len(digest)] = digest  # place hash at offset 95
    block = bytearray(V54)
    for i in range(V54):
        block[i] = U[i] ^ PADKEY[i]
    if block[0] == 0:
        block[0] ^= 1

    sig = encrypt(bytes(block))
    out = bytearray(128)
    out[0:len(sig)] = sig  # left-aligned, zero padded to 128 bytes
    return out.hex().upper()


def main():
    license = build_license()
    license["signature"] = sign(license["payload"])

    text = canonical(license)
    with open("idapro.hexlic", "w", encoding="utf-8") as f:
        f.write(text)
    print("License written to idapro.hexlic")
    print("Signature:", license["signature"])


if __name__ == "__main__":
    main()
