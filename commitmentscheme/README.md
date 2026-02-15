## Commitment scheme experimentation

This folder contains a small script to compute the binding/hiding break probabilities for the truncated-hash commitment scheme described in the assignment.

### Run

From the repo root:

```powershell
python .\commitmentscheme\commitment_probabilities.py --min-x 4 --max-x 48 --outdir .\commitmentscheme\out
```

### Outputs

- `commitmentscheme/out/probabilities.csv`
- `commitmentscheme/out/probabilities.png` (combined plot; requires `matplotlib`)
- `commitmentscheme/out/probabilities_binding.png` (binding-only; requires `matplotlib`)
- `commitmentscheme/out/probabilities_hiding.png` (hiding-only; requires `matplotlib`)

If you don’t have matplotlib:

```powershell
python -m pip install matplotlib
```
