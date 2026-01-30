# blockchain mining

Python helper for the blockchain mining assignment.

## What it does

1. Fetches a starter (length-2) blockchain from the server.
2. Mines 3 additional blocks so each new block hash starts with a 4-hex seed.
3. Submits the length-5 chain back to the server and prints the server reply.

## Run

From the repo root:

```powershell
python .\bcmining\miner.py --seed 0a72
```

Pick a random seed:

```powershell
python .\bcmining\miner.py --seed random
```

Mine but don’t submit:

```powershell
python .\bcmining\miner.py --seed 0a72 --no-submit
```

## Notes

- The timestamp format matches the assignment: `%Y-%m-%d, %H:%M:%S`.
- Hashing matches the assignment exactly:
  `sha256(f"{index}-{timestamp}-{data}-{prevhash}-{nonce}")`.
