"""
Simplified OTR client (Bob) for the Advanced Web Security assignment.

Implements:
- Diffie-Hellman key exchange
- Socialist Millionaire Protocol (SMP) check of x = SHA1(DH_key_bytes || passphrase)
- Secure chat message via XOR with DH key

All group operations are mod p in Z_p^*, with generator g = g1 = 2.


By:
Group 24: Prince Samuel Kyeremanteng and Hadar Eklund


"""

from __future__ import annotations

# standard library imports
# hashlib, base64, os, secrets, socket, dataclasses, pathlib, typing, re
import hashlib
import base64
import os
import secrets
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Protocol, runtime_checkable
import re

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
    # The assignment handout specifies that p should be loaded from a file, 
    # so we do that even if we have a hardcoded fallback.
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
    # Convert an integer to its minimal big-endian byte representation (no leading zeros).
    if x == 0:
        return b"\x00"
    return x.to_bytes((x.bit_length() + 7) // 8, "big")


def _inv_mod(a: int, p: int) -> int:
    # Compute the modular inverse of a mod p using Fermat's little theorem, since p is prime.
    return pow(a, p - 2, p)


@dataclass
class StreamCodec:
    # StreamCodec provides a convenient interface for sending/receiving integers and text messages over a socket-like object.
    sock: "SocketLike"
    buf: bytearray

    send_delimiter: bytes

    def __init__(self, sock: "SocketLike", *, send_delimiter: bytes = b"\n"):
        self.sock = sock
        self.buf = bytearray()
        self.send_delimiter = send_delimiter

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
        def _all_hex(bs: bytes) -> bool:
            for b in bs:
                c = chr(b).lower()
                if c not in "0123456789abcdef":
                    return False
            return True

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

            try:
                chunk = self._recv_more()
            except (TimeoutError, socket.timeout):
                # We realised that sometimes the server send integers as a single undelimited hex blob,
                # then wait for the next client message. In that case, a recv timeout
                # means "end of token" and so we parse what we have.
                token = bytes(self.buf).strip()
                if token and _all_hex(token):
                    self.buf.clear()
                    return int(token.decode("utf-8"), 16)
                raise

            if chunk == b"":
                # If the server closes after sending the token, parse the final buffer.
                token = bytes(self.buf).strip()
                if token and _all_hex(token):
                    self.buf.clear()
                    return int(token.decode("utf-8"), 16)
                raise ConnectionError("Socket closed while waiting for int")

    def send_int(self, num: int) -> None:
        payload = (format(num, "x")).encode("utf-8") + self.send_delimiter
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
                txt = token.decode("utf-8", errors="replace")
                if txt in ("ack", "nak"):
                    del self.buf[:3]
                    return txt
                # If it's not ack/nak, do NOT consume: it may belong to the next protocol field.

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


@runtime_checkable
class SocketLike(Protocol):
    # A minimal protocol for socket-like objects used by StreamCodec. 
    # This allows us to use either a raw TCP socket or a WebSocketConnection interchangeably.
    def recv(self, bufsize: int) -> bytes: ...
    def sendall(self, data: bytes) -> None: ...
    def settimeout(self, value: float | None) -> None: ...
    def close(self) -> None: ...


_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _ws_key() -> str:
    # Generate a random 16-byte value and return it base64-encoded as the Sec-WebSocket-Key.
    return base64.b64encode(secrets.token_bytes(16)).decode("ascii")


def _ws_accept_for_key(key: str) -> str:
    # Compute the expected Sec-WebSocket-Accept value for a given Sec-WebSocket-Key.
    digest = hashlib.sha1((key + _WS_GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


def _recv_until(sock: socket.socket, marker: bytes, *, limit: int = 65536) -> bytes:
    # Receive from the socket until the marker sequence is found, or limit is exceeded.
    data = bytearray()
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > limit:
            raise ValueError("WebSocket handshake too large")
    return bytes(data)


def _parse_http_headers(block: bytes) -> tuple[str, dict[str, str]]:
    # minimal HTTP response parsing
    try:
        head, _rest = block.split(b"\r\n\r\n", 1)
    except ValueError:
        head = block
    lines = head.split(b"\r\n")
    if not lines:
        raise ValueError("Empty HTTP response")
    status_line = lines[0].decode("iso-8859-1", errors="replace")
    headers: dict[str, str] = {}
    for raw in lines[1:]:
        if b":" not in raw:
            continue
        k, v = raw.split(b":", 1)
        headers[k.decode("iso-8859-1").strip().lower()] = v.decode("iso-8859-1").strip()
    return status_line, headers


def _ws_handshake(
    sock: socket.socket,
    *,
    host: str,
    port: int,
    path: str = "/",
    timeout_s: float = 10.0,
) -> None:
    if not path.startswith("/"):
        path = "/" + path

    key = _ws_key()
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "\r\n"
    ).encode("ascii")

    sock.settimeout(timeout_s)
    sock.sendall(req)

    resp = _recv_until(sock, b"\r\n\r\n")
    status_line, headers = _parse_http_headers(resp)
    if " 101 " not in status_line:
        # Give a short diagnostic. This commonly happens if the endpoint is raw TCP, not WS.
        preview = resp[:200].decode("iso-8859-1", errors="replace")
        raise ConnectionError(f"WebSocket upgrade failed: {status_line!r}. Response preview: {preview!r}")

    expected_accept = _ws_accept_for_key(key)
    accept = headers.get("sec-websocket-accept", "")
    if accept != expected_accept:
        raise ConnectionError("WebSocket upgrade failed: Sec-WebSocket-Accept mismatch")


class WebSocketConnection:
    """Very small WebSocket client (text frames) to avoid extra dependencies.

    Exposes a socket-like interface (recv/sendall/settimeout/close).
    Converts received WebSocket messages into a byte-stream by appending a newline
    after each complete message, which lets StreamCodec parse tokens reliably.
    """

    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._stream_buf = bytearray()
        self._timeout: float | None = None

    def settimeout(self, value: float | None) -> None:
        self._timeout = value
        self._sock.settimeout(value)

    def close(self) -> None:
        try:
            self._send_control(opcode=0x8, payload=b"")
        except Exception:
            pass
        self._sock.close()

    def sendall(self, data: bytes) -> None:
        # Most course servers treat each WS message as one logical token.
        payload = data.rstrip(b"\r\n")
        self._send_frame(opcode=0x1, payload=payload)

    def recv(self, bufsize: int) -> bytes:
        if bufsize <= 0:
            return b""
        while not self._stream_buf:
            self._recv_one_message_into_stream()
        out = bytes(self._stream_buf[:bufsize])
        del self._stream_buf[:bufsize]
        return out

    def _send_control(self, *, opcode: int, payload: bytes) -> None:
        self._send_frame(opcode=opcode, payload=payload)

    def _send_frame(self, *, opcode: int, payload: bytes) -> None:
        # Client-to-server frames must be masked.
        fin_opcode = 0x80 | (opcode & 0x0F)
        mask_bit = 0x80
        length = len(payload)

        header = bytearray([fin_opcode])
        if length <= 125:
            header.append(mask_bit | length)
        elif length <= 0xFFFF:
            header.append(mask_bit | 126)
            header.extend(length.to_bytes(2, "big"))
        else:
            header.append(mask_bit | 127)
            header.extend(length.to_bytes(8, "big"))

        mask = secrets.token_bytes(4)
        header.extend(mask)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self._sock.sendall(bytes(header) + masked)

    def _recv_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Socket closed while reading WebSocket frame")
            buf.extend(chunk)
        return bytes(buf)

    def _recv_one_message_into_stream(self) -> None:
        # Read a complete message (possibly fragmented) and append payload + '\n' to stream buf.
        payload_parts: list[bytes] = []
        msg_opcode: int | None = None

        while True:
            first2 = self._recv_exact(2)
            b1, b2 = first2[0], first2[1]
            fin = (b1 & 0x80) != 0
            opcode = b1 & 0x0F
            masked = (b2 & 0x80) != 0
            length = b2 & 0x7F

            if length == 126:
                length = int.from_bytes(self._recv_exact(2), "big")
            elif length == 127:
                length = int.from_bytes(self._recv_exact(8), "big")

            mask_key = b""
            if masked:
                mask_key = self._recv_exact(4)

            payload = self._recv_exact(length) if length else b""
            if masked and payload:
                payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))

            # Control frames
            if opcode == 0x8:  # close
                # acknowledge close and then stop
                try:
                    self._send_control(opcode=0x8, payload=b"")
                except Exception:
                    pass
                raise ConnectionError("WebSocket closed by server")
            if opcode == 0x9:  # ping
                self._send_control(opcode=0xA, payload=payload)
                continue
            if opcode == 0xA:  # pong
                continue

            if opcode in (0x1, 0x2):
                msg_opcode = opcode
            elif opcode == 0x0:
                # continuation
                if msg_opcode is None:
                    raise ConnectionError("Unexpected WebSocket continuation frame")
            else:
                # ignore unknown non-control opcodes
                continue

            if payload:
                payload_parts.append(payload)

            if fin:
                break

        message = b"".join(payload_parts)
        # Turn message boundaries into a newline delimiter for StreamCodec.
        self._stream_buf.extend(message)
        self._stream_buf.extend(b"\n")


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
    transport: str = "auto",
    ws_path: str = "/",
) -> str:
    """Run the full simplified OTR flow. Returns the server's final response text."""
    if p_file is None:
        p_file = Path(__file__).with_name("m2p3-p.bin")

    p = load_p_from_file(p_file)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout_s)
    s.connect((host, port))
    transport = transport.lower().strip()
    if transport not in ("auto", "tcp", "ws"):
        raise ValueError("transport must be 'auto', 'tcp', or 'ws'")

    sock_like: SocketLike
    send_delim = b"\n"
    if transport == "ws":
        _ws_handshake(s, host=host, port=port, path=ws_path, timeout_s=timeout_s)
        sock_like = WebSocketConnection(s)
        sock_like.settimeout(timeout_s)
        # send each token as its own WS message (no trailing newline in the payload)
        send_delim = b""
    elif transport == "tcp":
        sock_like = s
    else:
        # auto: safely detect HTTP-ish servers without consuming data
        try:
            s.settimeout(min(1.0, timeout_s))
            peek = s.recv(1, socket.MSG_PEEK)
        except (TimeoutError, socket.timeout):
            peek = b""
        finally:
            s.settimeout(timeout_s)

        if peek.startswith(b"H"):
            _ws_handshake(s, host=host, port=port, path=ws_path, timeout_s=timeout_s)
            sock_like = WebSocketConnection(s)
            sock_like.settimeout(timeout_s)
            send_delim = b""
        else:
            sock_like = s

    codec = StreamCodec(sock_like, send_delimiter=send_delim)

    try:
        # Support different initiator modes via dh_initiator: 'auto' | 'server' | 'client'.
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

        # Don’t block here: if no token arrives quickly, proceed to the secure chat.
        try:
            sock_like.settimeout(min(0.75, timeout_s))
            auth = codec.recv_ack()
            print("Authentication:", auth)
            if auth != "ack":
                raise ValueError("Server reported authentication failure")
        except (TimeoutError, socket.timeout):
            pass
        finally:
            sock_like.settimeout(timeout_s)

        # Secure chat
        m = int(message_hex, 16)
        enc = m ^ dh_key
        codec.send_int(enc)
        response = codec.recv_text_eof()
        m = re.search(r"[0-9a-fA-F]{40}", response)
        normalized = m.group(0).lower() if m else response.strip()
        print("Response:", normalized)
        return normalized
    finally:
        try:
            sock_like.close()
        except Exception:
            pass


if __name__ == "__main__":
    host = os.environ.get("OTR_HOST", "igor.eit.lth.se")
    port = int(os.environ.get("OTR_PORT", "6005"))
    msg = os.environ.get("OTR_MSG", "6274f2bc5f0b4a2c80f6e233c44dd6526aaef29e")
    # msg = os.environ.get("OTR_MSG", "1337")
    dh_init = os.environ.get("OTR_DH_INIT", "auto")  # 'auto' | 'server' | 'client'
    transport = os.environ.get("OTR_TRANSPORT", "auto")  # 'auto' | 'ws' | 'tcp'
    ws_path = os.environ.get("OTR_WS_PATH", "/")
    timeout_s = float(os.environ.get("OTR_TIMEOUT", "10"))
    run_otr_client(
        host,
        port,
        message_hex=msg,
        dh_initiator=dh_init,
        transport=transport,
        ws_path=ws_path,
        timeout_s=timeout_s,
    )
