# RSA OAEP (MGF1 + OAEP encode/decode)

Implements the OAEP padding scheme from RFC 8017 for the course assignment:
- `I2OSP`
- `MGF1` using **SHA-1**
- OAEP **encoding** and **decoding** (no RSA encryption/decryption)

Target encoded message size: **k = 128 bytes** (1024-bit RSA).

## Run self-test

From repo root (PowerShell):

```powershell
python .\rsa-oaep\run_oaep.py --selftest
```

## Interactive runner

```powershell
python .\rsa-oaep\run_oaep.py
```

## Files

- [rsa-oaep/rsa_oaep.py](rsa_oaep.py): Implementation
- [rsa-oaep/run_oaep.py](run_oaep.py): Interactive runner + test vectors
