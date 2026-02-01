"""
This program is an Interactive conversions runner to help with various data format conversions.
Written by:
- Prince Samuel Kyeremanteng
- Hadar Eklund


Run:
	python luhnalgorithm/run_conversions.py

This script prompts you for a conversion type and an input value, then uses the
predefined conversion functions in conversions.py.
"""

from __future__ import annotations

from conversions import (
	bytes_to_hex,
	bytes_to_int,
	hash_bytes,
	hex_to_bytes,
	hex_to_int,
	int_to_bytes,
	int_to_hash,
)


def _print_menu() -> None:
	print("\nChoose a conversion:")
	print("  1) int -> hex string (int_to_hash)")
	print("  2) hex string -> int (hex_to_int)")
	print("  3) int -> 4-byte big-endian bytes (int_to_bytes)")
	print("  4) bytes(hex input) -> int (bytes_to_int)")
	print("  5) hex string -> bytes (hex_to_bytes)")
	print("  6) bytes(hex input) -> hex string (bytes_to_hex)")
	print("  7) sha256(bytes(hex input)) -> hex digest (hash_bytes)")
	print("  q) quit")


def _prompt_int(prompt: str) -> int:
	while True:
		raw = input(prompt).strip()
		try:
			return int(raw)
		except ValueError:
			print("Invalid integer. Try again.")


def _prompt_hex(prompt: str) -> str:
	while True:
		raw = input(prompt).strip()
		if raw.startswith("0x") or raw.startswith("0X"):
			raw = raw[2:]
		raw = raw.replace(" ", "")

		if raw == "":
			print("Hex string cannot be empty. Try again.")
			continue

		try:
			bytes.fromhex(raw)
		except ValueError:
			print("Invalid hex string. Use only 0-9 and a-f. Try again.")
			continue

		return raw


def main() -> None:
	print("Conversions runner (using conversions.py)")

	while True:
		_print_menu()
		choice = input("> ").strip().lower()

		if choice in {"q", "quit", "exit"}:
			print("Goodbye.")
			return

		if choice == "1":
			num = _prompt_int("Enter integer: ")
			result = int_to_hash(num)
			print(f"Result: {result}")

		elif choice == "2":
			hex_str = input("Enter hex string (with or without 0x): ").strip()
			if hex_str.startswith("0x") or hex_str.startswith("0X"):
				hex_str = hex_str[2:]
			try:
				result = hex_to_int(hex_str)
			except ValueError:
				print("Invalid hex string. Try again.")
				continue
			print(f"Result: {result}")

		elif choice == "3":
			num = _prompt_int("Enter integer (0 to 2^32-1): ")
			try:
				b = int_to_bytes(num)
			except OverflowError:
				print("Number out of range for 4 bytes. Try again.")
				continue
			print(f"Result (bytes repr): {b!r}")
			print(f"Result (hex): {bytes_to_hex(b)}")

		elif choice == "4":
			hex_str = _prompt_hex("Enter bytes as hex (e.g., deadbeef): ")
			b = hex_to_bytes(hex_str)
			result = bytes_to_int(b)
			print(f"Result: {result}")

		elif choice == "5":
			hex_str = _prompt_hex("Enter hex string: ")
			b = hex_to_bytes(hex_str)
			print(f"Result (bytes repr): {b!r}")
			print(f"Result (hex): {bytes_to_hex(b)}")

		elif choice == "6":
			hex_str = _prompt_hex("Enter bytes as hex: ")
			b = hex_to_bytes(hex_str)
			result = bytes_to_hex(b)
			print(f"Result: {result}")

		elif choice == "7":
			hex_str = _prompt_hex("Enter bytes as hex to hash: ")
			b = hex_to_bytes(hex_str)
			result = hash_bytes(b)
			print(f"Result: {result}")

		else:
			print("Unknown option. Choose 1-7 or q.")


if __name__ == "__main__":
	main()
