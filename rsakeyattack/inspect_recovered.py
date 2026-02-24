from __future__ import annotations

import base64
from pathlib import Path


HERE = Path(__file__).resolve().parent


def read_len(buf: bytes, i: int) -> tuple[int, int]:
    first = buf[i]
    i += 1
    if first < 0x80:
        return first, i
    n = first & 0x7F
    length = int.from_bytes(buf[i : i + n], "big")
    i += n
    return length, i


def read_int(buf: bytes, i: int) -> tuple[int, int, bytes, int]:
    if buf[i] != 0x02:
        raise ValueError(f"Expected INTEGER at {i}, got 0x{buf[i]:02x}")
    i += 1
    l, i = read_len(buf, i)
    raw = buf[i : i + l]
    i += l
    val = int.from_bytes(raw, "big", signed=False)
    return val, l, raw, i


def extract_inner_rsaprivatekey_der(pkcs8_der: bytes) -> bytes:
    i = 0
    if pkcs8_der[i] != 0x30:
        raise ValueError("Not a DER SEQUENCE")
    i += 1
    seq_len, i = read_len(pkcs8_der, i)
    end = i + seq_len

    _version, _, _, i = read_int(pkcs8_der, i)

    if pkcs8_der[i] != 0x30:
        raise ValueError("Missing AlgorithmIdentifier")
    i += 1
    alg_len, i = read_len(pkcs8_der, i)
    i += alg_len

    if pkcs8_der[i] != 0x04:
        raise ValueError("Missing privateKey OCTET STRING")
    i += 1
    oct_len, i = read_len(pkcs8_der, i)
    inner = pkcs8_der[i : i + oct_len]
    if i + oct_len != end:
        # Attributes might exist, but for this assignment we expect none.
        pass
    return inner


def main() -> None:
    pem = (HERE / "key.pem").read_text("ascii")
    pem = pem.replace("censored", "")
    body = pem.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "")
    body = "".join(body.split())

    der = base64.b64decode(body)
    inner = extract_inner_rsaprivatekey_der(der)

    # Parse RSAPrivateKey
    i = 0
    if inner[i] != 0x30:
        raise ValueError("Inner key is not a SEQUENCE")
    i += 1
    seq_len, i = read_len(inner, i)
    end = i + seq_len

    version, _, _, i = read_int(inner, i)
    n, _, n_raw, i = read_int(inner, i)
    e, _, _, i = read_int(inner, i)
    d, _, _, i = read_int(inner, i)
    p, _, _, i = read_int(inner, i)
    q, _, _, i = read_int(inner, i)
    dp, _, _, i = read_int(inner, i)
    dq, _, _, i = read_int(inner, i)
    qi, _, _, i = read_int(inner, i)

    print("RSAPrivateKey version:", version)
    print("n_bits:", n.bit_length())
    print("e:", e)
    print("n leading bytes:", n_raw[:8].hex())
    print("parsed end offset:", i, "expected:", end)

    # Math checks
    ok_pq = (p * q == n)
    print("check p*q == n:", ok_pq)

    phi = (p - 1) * (q - 1)
    ok_ed = ((e * d) % phi == 1)
    print("check e*d mod phi == 1:", ok_ed)

    ok_dp = (dp == d % (p - 1))
    ok_dq = (dq == d % (q - 1))
    print("check dp == d mod (p-1):", ok_dp)
    print("check dq == d mod (q-1):", ok_dq)

    ok_qi = ((q * qi) % p == 1)
    print("check qInv:", ok_qi)


if __name__ == "__main__":
    main()
