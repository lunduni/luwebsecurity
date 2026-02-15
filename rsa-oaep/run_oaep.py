"""
Small runner for RSA OAEP assignment.

Run from repo root:
	python .\rsa-oaep\run_oaep.py --selftest

Or interactively:
	python .\rsa-oaep\run_oaep.py

By:
Group 24: Prince Samuel Kyeremanteng and Hadar Eklund
"""

from __future__ import annotations

# this is for parsing command-line args; the actual OAEP logic is in rsa_oaep.py.
import argparse

# imports from rsa_oaep.py, which implements the actual OAEP logic.
from rsa_oaep import bytes_to_hex, hex_to_bytes, mgf1, oaep_decode, oaep_encode


def _prompt_hex(prompt: str, *, allow_empty: bool = False) -> str:
	# This is a simple helper to prompt for hex input and validate it. 
	# It also allows optional spaces and "0x" prefix for convenience.
	while True:
		raw = input(prompt).strip()
		raw = raw.replace(" ", "") # Remove spaces for easier input
		if raw.startswith("0x") or raw.startswith("0X"):
			raw = raw[2:]
		if raw == "" and allow_empty:
			return ""
		try:
			bytes.fromhex(raw)
		except ValueError:
			print("Invalid hex string. Try again.")
			continue
		return raw


def _prompt_int(prompt: str) -> int:
	# Simple helper to prompt for an integer and validate it.
	while True:
		raw = input(prompt).strip()
		try:
			return int(raw)
		except ValueError:
			print("Invalid integer. Try again.")


def selftest() -> int:
	# MGF1 example from the assignment prompt
	# we only used this to verify our MGF1 implementation matches the provided test vector; 
	# not a full unit test suite. LOL
	seed_hex = "0123456789abcdef"
	mask_len = 30
	expected_mask_hex = "18a65e36189833d99e55a68dedda1cce13a494c947817d25dc80d9b4586a"
	mask = mgf1(hex_to_bytes(seed_hex), mask_len)
	ok_mgf1 = bytes_to_hex(mask) == expected_mask_hex

	# OAEP example from the assignment prompt
	m_hex = "fd5507e917ecbe833878"
	oaep_seed_hex = "1e652ec152d0bfcd65190ffc604c0933d0423381"
	expected_em_hex = (
		"0000255975c743f5f11ab5e450825d93b52a160aeef9d3778a18b7aa067f90b2"
		"178406fa1e1bf77f03f86629dd5607d11b9961707736c2d16e7c668b367890bc"
		"6ef1745396404ba7832b1cdfb0388ef601947fc0aff1fd2dcd279dabde9b10bf"
		"c51f40e13fb29ed5101dbcb044e6232e6371935c8347286db25c9ee20351ee82"
	)

	em = oaep_encode(hex_to_bytes(m_hex), hex_to_bytes(oaep_seed_hex), k=128)
	em_hex = bytes_to_hex(em)
	ok_encode = em_hex == expected_em_hex

	decoded = oaep_decode(hex_to_bytes(expected_em_hex), k=128)
	ok_decode = bytes_to_hex(decoded) == m_hex

	print("Self-test results:")
	print(f"  MGF1:       {'OK' if ok_mgf1 else 'FAIL'}")
	print(f"  OAEP encode:{'OK' if ok_encode else 'FAIL'}")
	print(f"  OAEP decode:{'OK' if ok_decode else 'FAIL'}")

	if not ok_mgf1:
		print(f"    got:      {bytes_to_hex(mask)}")
		print(f"    expected: {expected_mask_hex}")
	if not ok_encode:
		print(f"    got:      {em_hex}")
		print(f"    expected: {expected_em_hex}")
	if not ok_decode:
		print(f"    got:      {bytes_to_hex(decoded)}")
		print(f"    expected: {m_hex}")

	return 0 if (ok_mgf1 and ok_encode and ok_decode) else 1


def interactive() -> None:
	# This is a simple interactive loop to test MGF1, OAEP encode, and OAEP decode with hex input/output.
	print("RSA OAEP runner")	
	while True:
		print("\nChoose:")
		print("  1) MGF1 (SHA-1)")
		print("  2) OAEP encode (k=128)")
		print("  3) OAEP decode (k=128)")
		print("  q) quit")
		choice = input("> ").strip().lower()
		if choice in {"q", "quit", "exit"}:
			return

		if choice == "1":
			seed_hex = _prompt_hex("mgfSeed (hex): ")
			mask_len = _prompt_int("maskLen (decimal): ")
			mask = mgf1(hex_to_bytes(seed_hex), mask_len)
			print(bytes_to_hex(mask))

		elif choice == "2":
			m_hex = _prompt_hex("M (hex): ", allow_empty=True)
			seed_hex = _prompt_hex("seed (hex, 20 bytes / 40 hex chars): ")
			em = oaep_encode(hex_to_bytes(m_hex), hex_to_bytes(seed_hex), k=128)
			print(bytes_to_hex(em))

		elif choice == "3":
			em_hex = _prompt_hex("EM (hex, 128 bytes / 256 hex chars): ")
			m = oaep_decode(hex_to_bytes(em_hex), k=128)
			print(bytes_to_hex(m))
		else:
			print("Unknown option.")


def main() -> int:
	parser = argparse.ArgumentParser()
	# just a simple test to verify the implementation matches the provided test vectors;
	parser.add_argument("--selftest", action="store_true", help="run provided test vectors")
	args = parser.parse_args()

	if args.selftest:
		return selftest()

	interactive()
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
