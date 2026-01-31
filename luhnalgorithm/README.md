# Advanced Web Security Course Scripts

This repository contains utility scripts for the Advanced Web Security course, specifically for handling Luhn algorithm calculations and various data type conversions.

## Files

### `luhns.py`

This script calculates the missing digit (represented by 'X') in a number string to satisfy the Luhn algorithm checksum. The Luhn algorithm is commonly used to validate credit card numbers and other identification numbers.

**Usage:**

```bash
python luhns.py <filename>
```

The script expects a text file as an argument where each line contains a number string with exactly one 'X' acting as a placeholder for the unknown digit. It outputs the discovered digits concatenated together.

**Example Input File (`testin.txt`):**
```
7992739871X
```

### `conversions.py`

A utility module containing functions for common data type conversions and hashing used in crypto challenges or security tasks. Can be run interactively with
```bash
python -i conversions.py
```

**Functions:**

- `int_to_hash(num)`: Converts an integer to a hex string (without prefix).
- `hex_to_int(hex_str)`: Converts a hex string to an integer.
- `int_to_bytes(num)`: Converts a 4-byte integer to bytes (big-endian).
- `bytes_to_int(byte_data)`: Converts bytes to an integer (big-endian).
- `hex_to_bytes(hex_str)`: Converts a hex string to bytes.
- `bytes_to_hex(byte_data)`: Converts bytes to a hex string.
- `hash_bytes(byte_data)`: Computes the SHA-256 hash of byte data.

### `run_conversions.py`

Interactive menu wrapper around the functions in `conversions.py`. It prompts you to pick a conversion, asks for the input value, then prints the result.

**Usage:**

```bash
python run_conversions.py
```

**Notes:**

- Options that take “bytes” ask you to enter the bytes as a hex string (example: `deadbeef`).
- For “hex string” inputs, you can include `0x` or not.
