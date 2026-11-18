# Integral Cryptanalysis of Reduced-Round Kalyna — Reproducibility Code

This repository contains **15 standalone Python validation programs** for reduced-round
Kalyna (DSTU 7624:2014), covering five block/key-size variants. Each program tests
an integral distinguisher and the corresponding reduced-round *round-key candidate*
filtering procedure. The programs use NumPy and do not depend on other Python source
files from this repository.

**Scope:** These are empirical validation scripts. Candidate retention and sampled
wrong-key rejection are **not equivalent to exhaustive round-key searching or full
master-key recovery**. Weak-key experiments distinguish genuine expanded master keys
from artificially restricted independent round subkeys.

## Contents

| Variant | Python script | Distinguisher → filtering | Experimental key model |
| --- | --- | --- | --- |
| 128/128 | `Kalyna-128-128/kalyna128_128_3round_combined.py` | 2R → 3R | No weak-key restriction; genuine master keys |
| 128/128 | `Kalyna-128-128/kalyna128_128_4round_combined.py` | 3R → 4R | Restricted pre-whitening round subkey; synthetic model |
| 128/128 | `Kalyna-128-128/kalyna128_128_5round_combined.py` | 4R → 5R | No initial pre-whitening; restricted K(1); synthetic model |
| 128/256 | `Kalyna-128-256/kalyna128_256_4round_combined.py` | 2R → 4R | No weak-key restriction; genuine master keys |
| 128/256 | `Kalyna-128-256/kalyna128_256_5round_combined.py` | 3R → 5R | Restricted pre-whitening round subkey; synthetic model |
| 128/256 | `Kalyna-128-256/kalyna128_256_6round_combined.py` | 4R → 6R | No initial pre-whitening; restricted K(1); synthetic model |
| 256/256 | `Kalyna-256-256/kalyna256_256_3round_combined.py` | 2R → 3R | No weak-key restriction; genuine master keys |
| 256/256 | `Kalyna-256-256/kalyna256_256_4round_combined.py` | 3R → 4R | Two active bytes; Kpw[24] = 0; restricted model |
| 256/256 | `Kalyna-256-256/kalyna256_256_5round_combined.py` | 4R → 5R | Two active bytes; 16 zero Kpw bytes; restricted model |
| 256/512 | `Kalyna-256-512/kalyna256_512_4round_combined.py` | 2R → 4R | No weak-key restriction; genuine master keys |
| 256/512 | `Kalyna-256-512/kalyna256_512_5round_combined.py` | 3R → 5R | Two active bytes; **genuine conditioned master keys** with Kpw[24] = 0 |
| 256/512 | `Kalyna-256-512/kalyna256_512_6round_combined.py` | 4R → 6R | Two active bytes; 16 zero Kpw bytes; restricted model |
| 512/512 | `Kalyna-512-512/kalyna512_512_4round_combined.py` | 3R → 4R | No weak-key restriction; genuine master keys |
| 512/512 | `Kalyna-512-512/kalyna512_512_5round_combined.py` | 4R → 5R | Eight zero Kpw bytes; restricted model |
| 512/512 | `Kalyna-512-512/kalyna512_512_6round_combined.py` | 5R → 6R | No initial pre-whitening; eight zero K(1) bytes; restricted model |

Here `Kpw` means the initial modulo-addition pre-whitening subkey, while `K(1)`
means the first internal round subkey. A *no-pre-whitening* model does not apply
the initial modular key addition. The byte conditions, precise plaintext multiset
constructions, and nonweak controls are implemented and documented in each script.
Do not interchange the weak-key restrictions between variants or rounds.

### Important 512/512 key conditions

- **5-round filter** (4-round distinguisher, initial pre-whitening retained):
  `Kpw[i] = 0` for `i in {0,15,22,29,36,43,50,57}`.
- **6-round filter** (5-round distinguisher, **no initial pre-whitening**):
  `K(1)[i] = 0` for `i in {0,15,22,29,36,43,50,57}`.

## Requirements

- Python 3.10 or newer
- NumPy (`pip install -r requirements.txt`)
- Enough RAM and disk for the selected trial count; two-active-byte structures
  include 65,536 chosen plaintexts per multiset and may require substantial runtime.

## Quick start (Linux / Ubuntu)

From the top-level repository directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt

# Small initial smoke test (5 trials)
python3 Kalyna-512-512/kalyna512_512_6round_combined.py \
  --trials 5 --jobs 2 --out smoke_512_512_R6

# Published-style experiment configuration (1000 trials)
python3 Kalyna-512-512/kalyna512_512_6round_combined.py \
  --trials 1000 --jobs 4 --seed 20261117 --out KALYNA512_512_R6_REPLAY
```

To run another experiment, substitute the path of its `.py` script from the table.
Every script provides its own CLI flags; consult:

```bash
python3 Kalyna-256-512/kalyna256_512_5round_combined.py --help
```

Some programs support `--resume` for interrupted runs. Resume requires the same
experimental settings and output folder. Numerical vectors, reports, and per-trial
records are written to the output folder chosen with `--out`.

## Correct interpretation

- Integral balance is tested at the **internal pre-terminal-addition state**,
  not blindly on ciphertext bytes after modulo-`2^64` addition.
- Reported incorrect-key rejection is based on the sampled or structured guesses
  actually evaluated, **not the entire 64-/128-/256-bit terminal subkey space**.
- Some correct outer-key guesses admit multiple equivalent inner-key candidates.
  Programs retain the entire candidate set rather than assuming uniqueness.
- The restricted-subkey models do **not** by themselves demonstrate that a
  corresponding true master key exists under the official key schedule.
- The provided code is research software for reproducibility, not a production
  cryptographic library.

## Citation

If using this repository for a paper, add the final article citation, DOI, and
version/commit identifier after acceptance or publication. For anonymous review,
follow the journal's anonymity and supplementary-material requirements.
