from __future__ import annotations

import argparse
import base64
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


HERE = Path(__file__).resolve().parent
DEFAULT_KEY_IN = HERE / "key.pem"
DEFAULT_CIPHERTEXT_IN = HERE / "ciphertext.txt"
DEFAULT_KEY_OUT = HERE / "key_recovered.pem"


def _read_len(buf: bytes, i: int) -> tuple[int, int]:
    first = buf[i]
    i += 1
    if first < 0x80:
        return first, i
    n = first & 0x7F
    length = int.from_bytes(buf[i : i + n], "big")
    i += n
    return length, i


def _read_int(buf: bytes, i: int) -> tuple[int, bytes, int]:
    if buf[i] != 0x02:
        raise ValueError(f"Expected INTEGER at {i}, got 0x{buf[i]:02x}")
    i += 1
    l, i = _read_len(buf, i)
    raw = buf[i : i + l]
    i += l
    return int.from_bytes(raw, "big", signed=False), raw, i


def _extract_pkcs1_from_pkcs8(pkcs8_der: bytes) -> bytes:
    i = 0
    if pkcs8_der[i] != 0x30:
        raise ValueError("Not a DER SEQUENCE")
    i += 1
    seq_len, i = _read_len(pkcs8_der, i)
    end = i + seq_len

    _version, _raw, i = _read_int(pkcs8_der, i)

    if pkcs8_der[i] != 0x30:
        raise ValueError("Missing AlgorithmIdentifier")
    i += 1
    alg_len, i = _read_len(pkcs8_der, i)
    i += alg_len

    if pkcs8_der[i] != 0x04:
        raise ValueError("Missing privateKey OCTET STRING")
    i += 1
    oct_len, i = _read_len(pkcs8_der, i)
    pkcs1_der = pkcs8_der[i : i + oct_len]

    # If attributes are present, they would start after the octet string.
    _ = end  # keep for readability
    return pkcs1_der


def _parse_pkcs1_private_numbers(pkcs1_der: bytes) -> tuple[int, int, int, int, int, int, int, int, int]:
    i = 0
    if pkcs1_der[i] != 0x30:
        raise ValueError("PKCS#1 key is not a SEQUENCE")
    i += 1
    seq_len, i = _read_len(pkcs1_der, i)
    end = i + seq_len

    version, _raw, i = _read_int(pkcs1_der, i)
    n, _n_raw, i = _read_int(pkcs1_der, i)
    e, _raw, i = _read_int(pkcs1_der, i)
    d, _raw, i = _read_int(pkcs1_der, i)
    p, _raw, i = _read_int(pkcs1_der, i)
    q, _raw, i = _read_int(pkcs1_der, i)
    dp, _raw, i = _read_int(pkcs1_der, i)
    dq, _raw, i = _read_int(pkcs1_der, i)
    qi, _raw, i = _read_int(pkcs1_der, i)

    if i != end:
        raise ValueError("Unexpected trailing bytes in PKCS#1 key")

    return version, n, e, d, p, q, dp, dq, qi


def _normalize_pem(pem_bytes: bytes) -> bytes:
    # Ensure standard PEM newlines even if input is on one line.
    text = pem_bytes.decode("ascii", errors="strict").replace("\r\n", "\n").replace("\r", "\n")

    begin = "-----BEGIN PRIVATE KEY-----"
    end = "-----END PRIVATE KEY-----"

    if begin not in text or end not in text:
        raise ValueError("Input does not look like a PKCS#8 PRIVATE KEY PEM")

    header, rest = text.split(begin, 1)
    body, footer = rest.split(end, 1)

    body = "".join(body.split())  # strip all whitespace

    # Re-wrap base64 to 64-char lines for readability.
    wrapped = "\n".join(body[i : i + 64] for i in range(0, len(body), 64))
    normalized = f"{begin}\n{wrapped}\n{end}\n"
    return normalized.encode("ascii")


def recover_key_pem(censored_pem: bytes) -> bytes:
    # The assignment replaces a base64 substring with literal 'censored' text.
    # Removing those placeholders restores the original base64 stream.
    recovered = censored_pem.replace(b"censored", b"")
    return _normalize_pem(recovered)


def recover_rsa_private_key(censored_pem: bytes) -> rsa.RSAPrivateKey:
    """Recover an RSA private key even if its embedded modulus is corrupted.

    The provided key has a censorship artifact that corrupts the PKCS#1 modulus field `n`.
    The remaining private parameters (p, q, d, CRT values) are still consistent.
    We rebuild a valid RSA key by recomputing `n = p*q`.
    """

    recovered_pem = recover_key_pem(censored_pem)

    # Decode PKCS#8 DER.
    text = recovered_pem.decode("ascii", errors="strict")
    body = (
        text.replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "")
        .strip()
    )
    body = "".join(body.split())
    pkcs8_der = base64.b64decode(body, validate=True)
    pkcs1_der = _extract_pkcs1_from_pkcs8(pkcs8_der)

    version, n_bad, e, d, p, q, dp, dq, qi = _parse_pkcs1_private_numbers(pkcs1_der)
    if version != 0:
        raise ValueError(f"Unexpected RSAPrivateKey version {version}")

    n = p * q

    if n == n_bad:
        # If modulus isn't actually corrupted, just load normally.
        key = serialization.load_pem_private_key(recovered_pem, password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise TypeError(f"Expected RSA private key, got {type(key)!r}")
        return key

    # Rebuild a correct key from private numbers.
    private_numbers = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=dp,
        dmq1=dq,
        iqmp=qi,
        public_numbers=rsa.RSAPublicNumbers(e=e, n=n),
    )
    return private_numbers.private_key()


def decrypt(ciphertext: bytes, key: rsa.RSAPrivateKey) -> bytes:
    paddings: list[tuple[str, padding.AsymmetricPadding]] = [
        (
            "OAEP-SHA1",
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None),
        ),
        (
            "OAEP-SHA256",
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        ),
        ("PKCS1v15", padding.PKCS1v15()),
    ]

    last_error: Exception | None = None
    for name, pad in paddings:
        try:
            pt = key.decrypt(ciphertext, pad)
            print(f"Decryption succeeded with {name}")
            return pt
        except Exception as ex:  # noqa: BLE001
            last_error = ex

    raise RuntimeError(f"Failed to decrypt with common paddings. Last error: {last_error}")


def decode_base64_text(text: str) -> bytes:
    """Decode base64 that may contain whitespace/newlines or be URL-safe.

    Many assignment handouts wrap base64 across multiple lines. Python's
    base64 decoder with validate=True rejects whitespace, so we strip it.
    """

    s = text.strip()
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        s = s[1:-1].strip()

    # Remove all whitespace (newlines, spaces, tabs).
    s = "".join(s.split())

    # Add padding if missing.
    if len(s) % 4:
        s += "=" * (-len(s) % 4)

    try:
        return base64.b64decode(s, validate=True)
    except Exception:
        # URL-safe base64 uses '-' and '_' instead of '+' and '/'.
        return base64.urlsafe_b64decode(s)


def main() -> None:
    parser = argparse.ArgumentParser(description="Recover censored RSA key and decrypt ciphertext")
    parser.add_argument(
        "--key",
        type=Path,
        default=DEFAULT_KEY_IN,
        help="Path to censored PKCS#8 private key PEM (default: rsakeyattack/key.pem)",
    )
    parser.add_argument(
        "--ciphertext",
        type=Path,
        default=DEFAULT_CIPHERTEXT_IN,
        help="Path to base64 ciphertext file (default: rsakeyattack/ciphertext.txt)",
    )
    parser.add_argument(
        "--out-key",
        type=Path,
        default=DEFAULT_KEY_OUT,
        help="Where to write the recovered private key PEM (default: rsakeyattack/key_recovered.pem)",
    )
    args = parser.parse_args()

    censored_pem = args.key.read_bytes()
    key = recover_rsa_private_key(censored_pem)
    numbers = key.private_numbers().public_numbers
    print(f"Recovered RSA key: n_bits={numbers.n.bit_length()} e={numbers.e}")

    pem_out = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    args.out_key.write_bytes(pem_out)
    print(f"Wrote recovered key to: {args.out_key}")

    ciphertext_text = args.ciphertext.read_text(encoding="utf-8")
    ciphertext = decode_base64_text(ciphertext_text)

    plaintext = decrypt(ciphertext, key)
    try:
        print("Plaintext (utf-8):")
        print(plaintext.decode("utf-8"))
    except UnicodeDecodeError:
        print("Plaintext (raw bytes):")
        print(plaintext)


if __name__ == "__main__":
    main()
