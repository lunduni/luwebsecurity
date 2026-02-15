"""
RSA OAEP padding helpers (MGF1 + OAEP encode/decode).

Implements the pieces needed for RSAES-OAEP as specified in RFC 8017:
- I2OSP (Section 4.1)
- MGF1 (Appendix B.2.1) using SHA-1
- EME-OAEP encoding/decoding (Section 7.1) with L = empty string

Notes for the course assignment:
- This module implements OAEP *encoding* and *decoding* only (no RSA).
- The target encoded message length is k=128 bytes (1024-bit RSA).
- Inputs/outputs in this module are bytes; see run_oaep.py for hex I/O.

By:
Group 24: Prince Samuel Kyeremanteng and Hadar Eklund
"""

from __future__ import annotations

# uses the builtin hashlib for SHA-1, 
# We declare that this is not a secure hash but is what the assignment specifies.
import hashlib
from typing import Callable


HashFunc = Callable[[bytes], "hashlib._Hash"]


def i2osp(x: int, x_len: int) -> bytes:
	"""Integer-to-Octet-String primitive (RFC 8017, Section 4.1).

	Args:
		x: Non-negative integer to convert.
		x_len: Intended length of the output in octets.

	Returns:
		Big-endian octet string of length x_len.

	Raises:
		ValueError: If x is negative or too large to fit in x_len bytes.
	"""
	if x < 0:
		raise ValueError("i2osp: x must be non-negative")
	if x_len < 0:
		raise ValueError("i2osp: x_len must be non-negative")
	if x >= 256**x_len:
		raise ValueError("i2osp: integer too large")
	return x.to_bytes(x_len, byteorder="big")


def mgf1(mgf_seed: bytes, mask_len: int, *, hash_func: HashFunc = hashlib.sha1) -> bytes:
	"""Mask Generation Function MGF1 (RFC 8017, Appendix B.2.1).

	Args:
		mgf_seed: Seed from which mask is generated.
		mask_len: Intended length of mask in octets.
		hash_func: Hash constructor (default SHA-1 per assignment).

	Returns:
		mask_len bytes.

	Raises:
		ValueError: If mask_len is negative or too large.
	"""
	if mask_len < 0:
		raise ValueError("mgf1: mask_len must be non-negative")

	h_len = hash_func(b"").digest_size
	# RFC 8017 says maskLen must be <= 2^32 * hLen
	if mask_len > (2**32) * h_len:
		raise ValueError("mgf1: mask_len too large")

	count = (mask_len + h_len - 1) // h_len
	output = bytearray()
	for counter in range(count):
		c = i2osp(counter, 4)
		output.extend(hash_func(mgf_seed + c).digest())

	return bytes(output[:mask_len])


def _xor_bytes(a: bytes, b: bytes) -> bytes:
	if len(a) != len(b):
		raise ValueError("xor: inputs must have same length")
	return bytes(x ^ y for x, y in zip(a, b))


def oaep_encode(
	message: bytes,
	seed: bytes,
	*,
	k: int = 128,
	hash_func: HashFunc = hashlib.sha1,
	label: bytes = b"",
) -> bytes:
	"""EME-OAEP encoding (RFC 8017, Section 7.1.1).

	Args:
		message: Message M to encode.
		seed: Random seed of length hLen (for probabilistic padding).
		k: Intended length in octets of the encoded message (RSA modulus size).
		hash_func: Hash constructor (SHA-1 per assignment).
		label: Optional label L (assignment uses L = empty string).

	Returns:
		Encoded message EM of length k.

	Raises:
		ValueError: If inputs are invalid.
	"""
	h_len = hash_func(b"").digest_size
	m_len = len(message)

	if len(seed) != h_len:
		raise ValueError(f"oaep_encode: seed must be {h_len} bytes")
	if k < 2 * h_len + 2:
		raise ValueError("oaep_encode: k too small")
	if m_len > k - 2 * h_len - 2:
		raise ValueError("oaep_encode: message too long")

	l_hash = hash_func(label).digest()
	# PS = k - m_len - 2 * h_len - 2 zero bytes
	ps = b"\x00" * (k - m_len - 2 * h_len - 2)
	db = l_hash + ps + b"\x01" + message
	assert len(db) == k - h_len - 1

	db_mask = mgf1(seed, k - h_len - 1, hash_func=hash_func)
	masked_db = _xor_bytes(db, db_mask)
	seed_mask = mgf1(masked_db, h_len, hash_func=hash_func)
	masked_seed = _xor_bytes(seed, seed_mask)

	em = b"\x00" + masked_seed + masked_db
	assert len(em) == k
	return em


def oaep_decode(
	em: bytes,
	*,
	k: int = 128,
	hash_func: HashFunc = hashlib.sha1,
	label: bytes = b"",
) -> bytes:
	"""EME-OAEP decoding (RFC 8017, Section 7.1.2).

	Args:
		em: Encoded message EM.
		k: Length in octets of the encoded message (RSA modulus size).
		hash_func: Hash constructor (SHA-1 per assignment).
		label: Optional label L (assignment uses L = empty string).

	Returns:
		Recovered message M.

	Raises:
		ValueError: If decoding fails.
	"""
	h_len = hash_func(b"").digest_size

	if len(em) != k:
		raise ValueError("oaep_decode: invalid EM length")
	if k < 2 * h_len + 2:
		raise ValueError("oaep_decode: k too small")

	y = em[0]
	masked_seed = em[1 : 1 + h_len]
	masked_db = em[1 + h_len :]

	if y != 0:
		raise ValueError("oaep_decode: leading byte must be 0x00")

	seed_mask = mgf1(masked_db, h_len, hash_func=hash_func)
	seed = _xor_bytes(masked_seed, seed_mask)
	db_mask = mgf1(seed, k - h_len - 1, hash_func=hash_func)
	db = _xor_bytes(masked_db, db_mask)

	l_hash = hash_func(label).digest()
	l_hash_prime = db[:h_len]
	if l_hash_prime != l_hash:
		raise ValueError("oaep_decode: label hash mismatch")

	# db = lHash' || PS || 0x01 || M, with PS all zero bytes.
	rest = db[h_len:]
	try:
		sep_index = rest.index(b"\x01")
	except ValueError as exc:
		raise ValueError("oaep_decode: 0x01 separator not found") from exc

	ps = rest[:sep_index]
	if any(b != 0 for b in ps):
		raise ValueError("oaep_decode: non-zero byte in PS")

	message = rest[sep_index + 1 :]
	return message


def hex_to_bytes(hex_str: str) -> bytes:
	hex_str = hex_str.strip().lower().replace(" ", "")
	if hex_str.startswith("0x"):
		hex_str = hex_str[2:]
	if hex_str == "":
		return b""
	return bytes.fromhex(hex_str)


def bytes_to_hex(data: bytes) -> str:
	return data.hex()
