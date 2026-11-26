
# Integral Cryptanalysis of Reduced-Round Kalyna — Reproducibility Code

This repository contains **15 standalone Python validation programs** for reduced-round
Kalyna (DSTU 7624:2014), covering five block/key-size variants. Each program tests
an integral distinguisher and the corresponding reduced-round *round-key candidate*
filtering procedure. The programs use NumPy and do not depend on other Python source
files from this repository.

**Scope:** These are empirical validation scripts. Candidate retention and sampled
wrong-key rejection are **not equivalent to exhaustive round-key searching or full
master-key recovery**. The experiments distinguish genuine expanded master keys
from synthetic restricted round subkeys satisfying the prescribed odd/even
round-subkey rotation identities.

## Contents

| Variant | Python script | Distinguisher → filtering | Experimental key model |
| --- | --- | --- | --- |
| 128/128 | `Kalyna_128-128/kalyna128_128_3round_combined.py` | 2R → 3R | No weak-key restriction; genuine master keys |
| 128/128 | `Kalyna_128-128/kalyna128_128_4round_combined.py` | 3R → 4R | Restricted pre-whitening round subkey; synthetic model |
| 128/128 | `Kalyna_128-128/kalyna128_128_5round_combined.py` | 4R → 5R | No initial pre-whitening; restricted K(1); synthetic model |
| 128/256 | `Kalyna_128-256/kalyna128_256_4round_combined.py` | 2R → 4R | No weak-key restriction; genuine master keys |
| 128/256 | `Kalyna_128-256/kalyna128_256_5round_combined.py` | 3R → 5R | Restricted pre-whitening round subkey; synthetic model |
| 128/256 | `Kalyna_128-256/kalyna128_256_6round_combined.py` | 4R → 6R | No initial pre-whitening; restricted K(1); synthetic model |
| 256/256 | `Kalyna_256-256/kalyna256_256_3round_combined.py` | 2R → 3R | No weak-key restriction; genuine master keys |
| 256/256 | `Kalyna_256-256/kalyna256_256_4round_combined.py` | 3R → 4R | Two active bytes (6,7); no weak-key restriction; genuine master keys |
| 256/256 | `Kalyna_256-256/kalyna256_256_5round_combined.py` | 4R → 5R | Two-variable backward extension; eight zero Kpw bytes; synthetic model |
| 256/512 | `Kalyna_256-512/kalyna256_512_4round_combined.py` | 2R → 4R | No weak-key restriction; genuine master keys |
| 256/512 | `Kalyna_256-512/kalyna256_512_5round_combined.py` | 3R → 5R | Two active bytes (6,7); no weak-key restriction; genuine master keys |
| 256/512 | `Kalyna_256-512/kalyna256_512_6round_combined.py` | 4R → 6R | Two-variable backward extension; eight zero Kpw bytes; synthetic model |
| 512/512 | `Kalyna_512-512/kalyna512_512_4round_combined.py` | 3R → 4R | No weak-key restriction; genuine master keys |
| 512/512 | `Kalyna_512-512/kalyna512_512_5round_combined.py` | 4R → 5R | Eight zero Kpw bytes; restricted model |
| 512/512 | `Kalyna_512-512/kalyna512_512_6round_combined.py` | 5R → 6R | No initial pre-whitening; eight zero K(1) bytes; restricted model |

Here `Kpw` means the initial modulo-addition pre-whitening subkey, while `K(1)`
means the first internal round subkey. A *no-pre-whitening* model does not apply
the initial modular key addition. All byte positions are indexed from zero.
The byte conditions, precise plaintext multiset constructions, and applicable
nonweak controls are implemented and documented in the corresponding scripts.
Do not interchange the weak-key restrictions between variants or rounds.

### Important 256-bit block key conditions

- **3-round distinguisher** (4-round filtering for Kalyna-256/256 and
  5-round filtering for Kalyna-256/512):

  The plaintext multiset is defined by

  `P(x,y) = a xor x*e6 xor y*e7`,

  where `(x,y)` ranges over the complete Cartesian product GF(256) × GF(256).
  Positions 6 and 7 are the two most significant bytes of the first
  64-bit column. Modular pre-whitening preserves their joint uniformity
  for arbitrary fixed pre-whitening subkeys.

  **No pre-whitening or internal round-subkey restriction is required.**
  The admissible pre-whitening subkey fraction is 1. Both validation
  programs use genuine unrestricted expanded master keys.

- **4-round distinguisher** (5-round filtering for Kalyna-256/256 and
  6-round filtering for Kalyna-256/512):

  The backward-extended plaintext multiset is defined by

  `P4(x,y) = F^-1(F(0) xor x*e6 xor y*e7)`,

  where `F = MC o SR o SB`. The sufficient pre-whitening restriction is

  `Kpw[i] = 0` for `i in {0,1,14,15,20,21,26,27}`.

  The remaining 24 pre-whitening subkey bytes are unrestricted.
  Consequently, the admissible pre-whitening subkey space contains
  `2^192` values, corresponding to a fraction of `2^-64`.

  The experiments use synthetic restricted round subkeys satisfying
  the prescribed odd/even round-subkey rotation identities.
  Compatibility with genuine master keys is not established.

Both constructions use two disjoint plaintext multisets, each containing
`2^16` plaintexts, giving a total chosen-plaintext count of `2^17` for
the corresponding filtering procedures.

### Important 512/512 key conditions

- **5-round filter** (4-round distinguisher, initial pre-whitening retained):
  `Kpw[i] = 0` for `i in {0,15,22,29,36,43,50,57}`.
- **6-round filter** (5-round distinguisher, **no initial pre-whitening**):
  `K(1)[i] = 0` for `i in {0,15,22,29,36,43,50,57}`.

## Requirements

- Python 3.10 or newer
- NumPy 2.x (`pip install -r exhaustive_validation/requirements.txt`)
- Enough RAM and disk for the selected trial count; two-variable structures
  include 65,536 chosen plaintexts per multiset and may require substantial runtime.

## Quick start (Linux / Ubuntu)

From the top-level repository directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r exhaustive_validation/requirements.txt

# Small initial smoke test (5 trials)
python3 Kalyna_512-512/kalyna512_512_6round_combined.py \
  --trials 5 --jobs 2 --out smoke_512_512_R6

# Full validation run (1000 trials)
python3 Kalyna_512-512/kalyna512_512_6round_combined.py \
  --trials 1000 --jobs 4 --seed 20261117 --out KALYNA512_512_R6_REPLAY
```

To run another experiment, substitute the path of its `.py` script from the table.
Every script provides its own CLI flags; consult:

```bash
python3 Kalyna_256-512/kalyna256_512_5round_combined.py --help
```

Some programs support `--resume` for interrupted runs. Resume requires the same
experimental settings, source code, and output folder. To perform a fresh experiment,
select a new output directory using `--out`.

Numerical test vectors, reports, and per-trial records are written to the output
folder chosen with `--out`.

## Correct interpretation

- Integral balance is tested at the **internal distinguisher output state**,
  before the appended filtering rounds and terminal modular addition,
  not blindly on ciphertext bytes after modulo-`2^64` addition.
- Reported incorrect-key rejection is based on the sampled or structured guesses
  actually evaluated, **not the entire terminal subkey space**.
- Column-wise filtering and full-state filtering are distinct procedures.
  Candidate counts refer to the corresponding search unit.
- Some correct outer-key guesses admit multiple equivalent inner-key candidates.
  Programs retain the candidate sets rather than assuming uniqueness.
- The admissible restricted-subkey fractions refer to the specified round-subkey
  spaces and do not necessarily represent fractions of genuine master keys.
- The restricted-subkey models do **not** by themselves demonstrate that a
  corresponding true master key exists under the official key schedule.
- Nominal filtering complexities are expressed in the operation units specified
  in the corresponding scripts and should not be interpreted as equivalent
  numbers of full encryptions.
- The provided code is research software for reproducibility, not a production
  cryptographic library.

## Exhaustive validation

Additional experiments are available in the
[exhaustive_validation](exhaustive_validation/)
directory.

These experiments examine wrong-key filtering using a 16-bit Kalyna-like model
and selected 16-bit terminal-subkey slices of Kalyna-128/128.

The toy-model experiment exhaustively enumerates all `2^16` terminal-key
candidates in each trial. The real-Kalyna experiments exhaustively enumerate
all `2^16` candidate values within selected two-byte slices of a 64-bit
terminal-subkey column, while holding the remaining six bytes at their
correct values.

These experiments provide exhaustive evidence within the specified search
spaces, not an exhaustive search over the complete Kalyna terminal-subkey
space. The toy model is not standardized Kalyna, and its wrong-key survivor
counts should not be interpreted directly as false-positive probabilities
for the full cipher.

The directory contains the implementation, archived experimental results,
verification script, and commands for reproducing the tests.

To verify the archived results:

```bash
cd exhaustive_validation
python3 verify_results.py
```

Further instructions for independently reproducing the exhaustive searches
are provided in the README of that directory.

## Citation

If using this repository for a paper, add the final article citation, DOI, and
version/commit identifier after acceptance or publication. For anonymous review,
follow the journal's anonymity and supplementary-material requirements.

