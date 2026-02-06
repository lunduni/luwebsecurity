#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""Simplified OTR client (Bob) for the Advanced Web Security assignment.

Implements:
- Diffie-Hellman key exchange
- Socialist Millionaire Protocol (SMP) check of x = SHA1(DH_key_bytes || passphrase)
- Secure chat message via XOR with DH key

All group operations are mod p in Z_p^*, with generator g = g1 = 2.

This code is designed to be importable and also runnable as a script.
"""

from __future__ import annotations

import hashlib
import os
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:
    # Reuse helper from the earlier DH assignment.
    from diffiehelman.dh.dh_client import (
        G_DEFAULT as _G_DEFAULT,
        P_1536 as _P_1536,
        generate_random as _generate_random,
    )
except Exception:
    _G_DEFAULT = None
    _P_1536 = None
    _generate_random = None


PASS_PHRASE = b"eitn41 <3"
G = int(_G_DEFAULT) if _G_DEFAULT is not None else 2


def load_p_from_file(p_file: Path) -> int:
    data = p_file.read_bytes()
    p = int.from_bytes(data, "big")
    if _P_1536 is not None and p != int(_P_1536):
        raise ValueError("Loaded p from file does not match expected 1536-bit prime")
    return p


def generate_random(modulus: int, bits: int = 1536) -> int:
    """Generate a random number then reduce mod modulus.

    Prefer the shared implementation from `diffiehelman.dh.dh_client` when available.
    """
    if _generate_random is not None:
        return _generate_random(modulus, bits=bits)

    byte_len = bits // 8
    rnd = os.urandom(byte_len)
    while rnd[0] < 128:
        rnd = os.urandom(byte_len)
    rnd_int = int("".join(format(i, "x") for i in rnd), 16)
    return rnd_int % modulus


def _random_exponent(p: int) -> int:
    """Return an exponent in the range [2, p-2]."""
    if p <= 5:
        raise ValueError("p too small")
    return generate_random(p - 3) + 2


def _int_to_min_bytes(x: int) -> bytes:
    if x == 0:
        return b"\x00"
    return x.to_bytes((x.bit_length() + 7) // 8, "big")


def _inv_mod(a: int, p: int) -> int:
    return pow(a, p - 2, p)


@dataclass
class StreamCodec:
    sock: socket.socket
    buf: bytearray

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buf = bytearray()

    def _recv_more(self) -> bytes:
        chunk = self.sock.recv(8192)
        if chunk:
            self.buf.extend(chunk)
        return chunk

    def peek_byte(self) -> int:
        """Ensure at least one byte is buffered and return it without consuming."""
        while not self.buf:
            chunk = self._recv_more()
            if chunk == b"":
                raise ConnectionError("Socket closed while waiting for data")
        return self.buf[0]

    def recv_int(self) -> int:
        """Receive a hex-encoded integer.

        Primary delimiter: newline. Fallback: parse contiguous hex prefix.
        """
        while True:
            nl = self.buf.find(b"\n")
            if nl != -1:
                token = bytes(self.buf[:nl]).strip()
                del self.buf[: nl + 1]
                if not token:
                    continue
                return int(token.decode("utf-8"), 16)

            # fallback: if buffer contains a non-hex byte after some hex digits
            # allow extraction without newline.
            if self.buf:
                i = 0
                while i < len(self.buf) and chr(self.buf[i]).lower() in "0123456789abcdef":
                    i += 1
                if i > 0 and (i < len(self.buf)):
                    token = bytes(self.buf[:i])
                    del self.buf[:i]
                    return int(token.decode("utf-8"), 16)

            chunk = self._recv_more()
            if chunk == b"":
                raise ConnectionError("Socket closed while waiting for int")

    def send_int(self, num: int) -> None:
        payload = (format(num, "x") + "\n").encode("utf-8")
        self.sock.sendall(payload)

    def recv_ack(self) -> str:
        """Receive an ack/nak string.

        Handles either newline-delimited text or bare 'ack'/'nak' with no delimiter.
        """
        # first try newline-delimited
        while True:
            nl = self.buf.find(b"\n")
            if nl != -1:
                token = bytes(self.buf[:nl]).strip()
                del self.buf[: nl + 1]
                if not token:
                    continue
                return token.decode("utf-8", errors="replace")

            # fallback: fixed 3 bytes
            if len(self.buf) >= 3:
                token = bytes(self.buf[:3])
                del self.buf[:3]
                txt = token.decode("utf-8", errors="replace")
                if txt in ("ack", "nak"):
                    return txt
                # if it's not ack/nak, keep reading as line-ish text

            chunk = self._recv_more()
            if chunk == b"":
                raise ConnectionError("Socket closed while waiting for ack/nak")

    def recv_text_eof(self) -> str:
        """Read remaining text until the server closes the connection."""
        chunks = [bytes(self.buf)]
        self.buf.clear()
        while True:
            chunk = self.sock.recv(8192)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks).decode("utf-8", errors="replace").strip()


def _derive_x(dh_key: int, passphrase: bytes = PASS_PHRASE) -> int:
    dh_bytes = _int_to_min_bytes(dh_key)
    digest = hashlib.sha1(dh_bytes + passphrase).digest()
    return int.from_bytes(digest, "big")


def run_otr_client(
    host: str,
    port: int,
    *,
    p_file: Optional[Path] = None,
    message_hex: str = "1337",
    dh_initiator: str = "auto",
    timeout_s: float = 10.0,
) -> str:
    """Run the full simplified OTR flow. Returns the server's final response text."""
    if p_file is None:
        p_file = Path(__file__).with_name("m2p3-p.bin")

    p = load_p_from_file(p_file)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout_s)
    s.connect((host, port))

    codec = StreamCodec(s)

    try:
        # DH Kex
        # Most handouts show server-first (Alice sends g^x1). Some deployments may be client-first.
        # Support both via dh_initiator: 'auto' | 'server' | 'client'.
        x2 = _random_exponent(p)
        g_x2 = pow(G, x2, p)

        g_x1: int
        if dh_initiator not in ("auto", "server", "client"):
            raise ValueError("dh_initiator must be 'auto', 'server', or 'client'")

        if dh_initiator in ("server", "auto"):
            try:
                # try server-first with a shorter initial wait when auto
                if dh_initiator == "auto":
                    s.settimeout(min(2.0, timeout_s))
                g_x1 = codec.recv_int()
            except TimeoutError:
                if dh_initiator == "server":
                    raise
                g_x1 = -1  # sentinel
            finally:
                s.settimeout(timeout_s)

            if g_x1 != -1:
                codec.send_int(g_x2)
                dh_ack = codec.recv_ack()
                print("Alice received g^x2?", dh_ack)
                dh_key = pow(g_x1, x2, p)
            else:
                # fallback to client-first
                codec.send_int(g_x2)
                # server may send ack/nak then g^x1, or g^x1 then ack/nak; try to infer
                first = chr(codec.peek_byte()).lower()
                if first in "0123456789abcdef":
                    g_x1 = codec.recv_int()
                    dh_ack = codec.recv_ack()
                else:
                    dh_ack = codec.recv_ack()
                    g_x1 = codec.recv_int()
                print("Alice received g^x2?", dh_ack)
                dh_key = pow(g_x1, x2, p)
        else:
            # client-first
            codec.send_int(g_x2)
            first = chr(codec.peek_byte()).lower()
            if first in "0123456789abcdef":
                g_x1 = codec.recv_int()
                dh_ack = codec.recv_ack()
            else:
                dh_ack = codec.recv_ack()
                g_x1 = codec.recv_int()
            print("Alice received g^x2?", dh_ack)
            dh_key = pow(g_x1, x2, p)

        # shared secret x for SMP
        # Reduce x mod (p-1) since exponents live in Z_(p-1)
        x = _derive_x(dh_key) % (p - 1)

        # SMP
        g_a2 = codec.recv_int()
        b2 = _random_exponent(p)
        g_b2 = pow(G, b2, p)
        codec.send_int(g_b2)
        b2_ack = codec.recv_ack()
        print("Alice received g^b2?", b2_ack)
        g2 = pow(g_a2, b2, p)  # g1^(a2*b2)

        g_a3 = codec.recv_int()
        b3 = _random_exponent(p)
        g_b3 = pow(G, b3, p)
        codec.send_int(g_b3)
        b3_ack = codec.recv_ack()
        print("Alice received g^b3?", b3_ack)
        g3 = pow(g_a3, b3, p)  # g1^(a3*b3)

        Pa = codec.recv_int()
        r = _random_exponent(p)
        Pb = pow(g3, r, p)
        if Pa == Pb:
            # extremely unlikely, but assignment hints to assert Pa != Pb
            raise ValueError("Unexpected Pa == Pb; retry")
        codec.send_int(Pb)
        pb_ack = codec.recv_ack()
        print("Alice received Pb?", pb_ack)

        Qa = codec.recv_int()
        # Qb = g1^r * g2^x mod p
        Qb = (pow(G, r, p) * pow(g2, x, p)) % p
        if Qa == Qb:
            # also extremely unlikely; assignment hints to assert Qa != Qb
            raise ValueError("Unexpected Qa == Qb; retry")
        codec.send_int(Qb)
        qb_ack = codec.recv_ack()
        print("Alice received Qb?", qb_ack)

        Qab_a3 = codec.recv_int()  # (Qa*Qb^-1)^a3
        ratio = (Qa * _inv_mod(Qb, p)) % p
        Qab_b3 = pow(ratio, b3, p)
        codec.send_int(Qab_b3)
        qabb3_ack = codec.recv_ack()
        print("Alice received (QaQb^-1)^b3?", qabb3_ack)

        # Verify SMP condition: c == Pa * Pb^-1 iff x matches
        c = pow(Qab_a3, b3, p)
        expected = (Pa * _inv_mod(Pb, p)) % p
        if c != expected:
            raise ValueError("SMP verification failed (c != Pa*Pb^-1)")

        auth = codec.recv_ack()
        print("Authentication:", auth)
        if auth != "ack":
            raise ValueError("Server reported authentication failure")

        # Secure chat
        m = int(message_hex, 16)
        enc = m ^ dh_key
        codec.send_int(enc)
        response = codec.recv_text_eof()
        print("Response:", response)
        return response
    finally:
        try:
            s.close()
        except Exception:
            pass


if __name__ == "__main__":
    host = os.environ.get("OTR_HOST", "igor.eit.lth.se")
    port = int(os.environ.get("OTR_PORT", "6005"))
    # msg = os.environ.get("OTR_MSG", "0123456789abcdef")
    msg = os.environ.get("OTR_MSG", "1337")
    dh_init = os.environ.get("OTR_DH_INIT", "auto")  # 'auto' | 'server' | 'client'
    run_otr_client(host, port, message_hex=msg, dh_initiator=dh_init)
