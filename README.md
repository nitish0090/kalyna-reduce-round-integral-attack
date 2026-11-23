# Exhaustive small-scale and structured wrong-key validation for Kalyna

Supplementary reproducibility code for the major revision of **Integral Cryptanalysis of Reduced-Round Kalyna with Modular Whitening**. This directory accompanies the existing 15 Kalyna validation programs and does **not** replace them.

## What is tested

**A. Fully exhaustive 16-bit *toy* model.** A deliberately reduced, **nonstandard Kalyna-like** SPN has four 4-bit nibbles (two 8-bit columns), a bijective 4-bit PRESENT S-box, two-row ShiftRows, a GF(16) MDS diffusion layer `[[1,2],[2,1]]` over `GF(2)[x]/(x^4+x+1)`, XOR internal round keys, and addition modulo `2^8` for pre- and post-whitening. Its four 16-bit key values (initial, two internal, final) are sampled independently; it does *not* use the Kalyna key schedule. Each trial uses two disjoint 16-text multisets with an active highest nibble. After two internal rounds, all four nibbles are XOR-balanced. The program encrypts a three-round target and enumerates **every one of the `2^16` terminal-subkey candidates**, applying inverse modular whitening and one inverse SPN round. The purpose is to **measure wrong-key survivors exactly within each sampled toy trial**, including possible nonuniqueness—not to predict full-Kalyna probabilities.

**B. Exhaustive *conditional* two-byte slices of actual Kalyna-128/128.** Genuine 128-bit master keys are expanded by the Kalyna key schedule in `kalyna_reference.py`. Each trial uses two disjoint, complete **256-plaintext multisets** and a three-round target whose two-round internal-state integral is verified. For one 64-bit terminal-key column, the program enumerates **all 65,536 values of two specified key bytes**, holding the other six bytes at the **correct** values. This is exhaustive **within the specified 16-bit slice only**; it is **not** exhaustive over all `2^64` column keys, all `2^128` master keys, or the other Kalyna variants.

## Contents

| File | Purpose |
|---|---|
| `exhaustive_validation.py` | Both experiments; NumPy-vectorized key-slice enumeration and CLI |
| `kalyna_reference.py` | **Unmodified source contents** of the existing `Kalyna_128-128/kalyna128_128_3round_combined.py`, copied and renamed so the supplement works independently |
| `verify_results.py` | Check the archived results, source SHA-256 and optionally compare fresh reruns |
| `requirements.txt` | Python dependency |
| `results/replay_results.json` | 256 exhaustive toy trials **and** actual Kalyna column 0, byte slice `(0,7)` |
| `results/real_low2.json` | Actual Kalyna column 0, byte slice `(0,1)` |
| `results/real_high2.json` | Actual Kalyna column 0, byte slice `(6,7)` |
| `results/real_col1.json` | Actual Kalyna column 1, byte slice `(0,7)` |

The reference module is the same implementation used in the existing 3-round Kalyna-128/128 experiment. Its SHA-256 (file **contents**, not filename) is `8a39cadb8dbf161d1a534b46f319c8b7f6d512224b50faf05fc2345d5a45eead`. It is imported, not executed as a separate command. The real-key-slice results store this hash for provenance.

## Requirements and quick verification

Python 3.10+ and NumPy 2.x. In the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r exhaustive_validation/requirements.txt
cd exhaustive_validation
python verify_results.py
```

`verify_results.py` checks internal consistency of the four archived files and confirms that their reference-code hash matches `kalyna_reference.py`. **That is an archive check, not a substitute for rerunning the experiments.**

## Reproduce the four saved result files

From inside `exhaustive_validation/` (after activating the virtual environment):

```bash
mkdir -p rerun

# All 2^16 toy terminal keys in each of 256 trials;
# plus column 0 / variable key bytes 0 and 7 in four genuine-key trials
python exhaustive_validation.py \
  --mode both --seed 20261119 --toy-trials 256 \
  --real-trials 4 --real-batch 128 \
  --real-column 0 --real-bytes 0 7 \
  --output rerun/replay_results.json

# The three remaining real-Kalyna structured slices
python exhaustive_validation.py \
  --mode real --seed 20261119 --real-trials 4 --real-batch 128 \
  --real-column 0 --real-bytes 0 1 --output rerun/real_low2.json

python exhaustive_validation.py \
  --mode real --seed 20261119 --real-trials 4 --real-batch 128 \
  --real-column 0 --real-bytes 6 7 --output rerun/real_high2.json

python exhaustive_validation.py \
  --mode real --seed 20261119 --real-trials 4 --real-batch 128 \
  --real-column 1 --real-bytes 0 7 --output rerun/real_col1.json

# Check all archived and newly generated cryptographic outputs.
# Elapsed wall-clock seconds are excluded from the comparison.
python verify_results.py --rerun-dir rerun
```

A fast smoke test is also available:

```bash
python exhaustive_validation.py --mode both \
  --toy-trials 2 --real-trials 1 \
  --real-batch 128 --output smoke.json
```

For long experiments use the same `--seed` shown above; time fields depend on the machine. The saved results were produced with NumPy 2.3.5; the command-line summary totals were also independently reproduced by the manuscript authors using NumPy 2.5.5.

## Archived result summary

| Model / key slice | Trials | Candidate evaluations | Correct retained | Incorrect survivors after 1st / both multisets |
|---|---:|---:|---:|---:|
| 16-bit toy: entire terminal-key space | 256 | 16,777,216 | 256/256 | 1,974 / **772** |
| Kalyna-128/128: column 0, bytes `(0,7)` | 4 | 262,144 | 4/4 | 0 / 0 |
| Kalyna-128/128: column 0, bytes `(0,1)` | 4 | 262,144 | 4/4 | 0 / 0 |
| Kalyna-128/128: column 0, bytes `(6,7)` | 4 | 262,144 | 4/4 | 0 / 0 |
| Kalyna-128/128: column 1, bytes `(0,7)` | 4 | 262,144 | 4/4 | 0 / 0 |
| **Real-Kalyna totals** | **16** | **1,048,576** | **16/16** | **0 / 0** |

All 256 toy trials had at least one additional wrong-key survivor, so the toy results explicitly illustrate **nonunique key-candidate filtering**. The real slice tests rejected every incorrect candidate in the **restricted** search regions with the other 48 bits of the tested 64-bit column fixed correctly; those results cannot be extrapolated to unrestricted wrong keys or other algorithms. Across the four slice experiments, `1,048,560` evaluations were incorrect candidates. Because different slices can overlap, counts are **candidate evaluations**, not necessarily distinct subkeys.

## Scope for reviewers

- The correct terminal key was retained for both multisets in every archived trial. The toy exhaustive trials also found wrong survivors, disproving any unconditional *uniqueness* conclusion from this type of integral test.
- The toy model and the real-Kalyna experiment are **different ciphers and key settings**; their observed frequencies are not interchangeable.
- No full `2^64`/`2^128` exhaustive search or complete master-key recovery is claimed, and the work estimates in the manuscript remain **nominal partial-decryption counts** rather than full-encryption equivalents.
- The real slice experiment validates the **Kalyna-128/128 three-round target** (Algorithm 1's column filtering). It does **not** exhaustively validate Algorithms 2–4 or every configuration in the manuscript; separate sampled trials are documented by the 15 variant scripts.

For questions about reproducing the main manuscript's other reduced-round configurations, see the top-level repository README and its 15 original Python scripts.
