
# Exhaustive validation experiments for Kalyna

This directory contains two additional experiments for the integral cryptanalysis of reduced-round Kalyna: an exhaustive terminal-key search in a 16-bit Kalyna-like model and exhaustive searches over selected two-byte subspaces of a Kalyna-128/128 terminal-subkey column. These tests supplement the 15 reduced-round validation programs in the main repository.

## 1. Experiments

### 1.1. 16-bit Kalyna-like model

The small-scale model is a nonstandard 16-bit substitution-permutation network. Its state consists of four 4-bit cells arranged in two 8-bit columns. It uses the PRESENT 4-bit S-box, a two-row ShiftRows operation, and the MixColumns matrix

```text
[1 2]
[2 1]
```

over GF(16), with irreducible polynomial `x^4 + x + 1`. Internal round keys are added using XOR; initial and terminal whitening use addition modulo `2^8` in each column. The initial key, two internal keys, and terminal key are independent 16-bit values; the model does not use Kalyna's key schedule.

Each trial uses two disjoint plaintext multisets of 16 texts, with one active most-significant nibble per structure. The state after two internal rounds is checked for XOR-balancedness in all four cells. We then encrypt through a third round and test all `2^16` terminal-key candidates by reversing the terminal modular addition and one round. The number of incorrect candidates satisfying the integral test is counted after the first multiset and after both multisets.

This experiment enumerates the entire terminal-key space of the toy model for each sampled set of round keys. It does not enumerate all combinations of the independently chosen toy round keys.

### 1.2. Kalyna-128/128: selected two-byte key slices

The second experiment uses Kalyna-128/128 with genuine 128-bit master keys and the standard key schedule. Each trial generates two disjoint 256-plaintext multisets, verifies the two-round internal-state integral, and encrypts the corresponding three-round target.

For one selected 64-bit terminal-subkey column, the program varies two specified key bytes over all `2^16` combinations. The other six bytes are held at their correct values. The resulting candidates are tested by the column-wise partial-decryption procedure.

Four slices are included:

| Column | Variable byte positions | Result file |
|---|---|---|
| 0 | `(0, 7)` | `results/replay_results.json` |
| 0 | `(0, 1)` | `results/real_low2.json` |
| 0 | `(6, 7)` | `results/real_high2.json` |
| 1 | `(0, 7)` | `results/real_col1.json` |

Byte positions are numbered from 0 to 7 within a 64-bit column. These tests are exhaustive only in the specified 16-bit slices, not over the complete `2^64` column-key space.

## 2. Files

| File | Description |
|---|---|
| `exhaustive_validation.py` | Runs the toy-model exhaustive search and the Kalyna-128/128 two-byte-slice experiments |
| `kalyna_reference.py` | Local copy of `Kalyna_128-128/kalyna128_128_3round_combined.py`, used for the genuine Kalyna operations |
| `verify_results.py` | Checks the saved output files and optionally compares them with fresh runs |
| `requirements.txt` | Python dependency specification |
| `results/replay_results.json` | Toy-model results and Kalyna column 0, bytes `(0,7)` |
| `results/real_low2.json` | Kalyna column 0, bytes `(0,1)` |
| `results/real_high2.json` | Kalyna column 0, bytes `(6,7)` |
| `results/real_col1.json` | Kalyna column 1, bytes `(0,7)` |

The reference implementation was copied without changing its source contents. Its SHA-256 is:

```text
8a39cadb8dbf161d1a534b46f319c8b7f6d512224b50faf05fc2345d5a45eead
```

The verification script checks this hash against the archived real-Kalyna results.

## 3. Requirements

- Python 3.10 or later
- NumPy 2.x

From the repository root, create a virtual environment and install the dependency:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r exhaustive_validation/requirements.txt
cd exhaustive_validation
```

To check the saved result files without rerunning the searches:

```bash
python verify_results.py
```

This checks the recorded counts, per-trial consistency, and reference-file hash. It does not independently recompute the cryptographic experiments.

## 4. Reproducing the results

Run the following commands from `exhaustive_validation/` with the virtual environment activated.

```bash
mkdir -p rerun

# 256 toy trials and Kalyna column 0, variable bytes (0,7)
python exhaustive_validation.py \
  --mode both --seed 20261119 --toy-trials 256 \
  --real-trials 4 --real-batch 128 \
  --real-column 0 --real-bytes 0 7 \
  --output rerun/replay_results.json

# Kalyna column 0, variable bytes (0,1)
python exhaustive_validation.py \
  --mode real --seed 20261119 --real-trials 4 --real-batch 128 \
  --real-column 0 --real-bytes 0 1 \
  --output rerun/real_low2.json

# Kalyna column 0, variable bytes (6,7)
python exhaustive_validation.py \
  --mode real --seed 20261119 --real-trials 4 --real-batch 128 \
  --real-column 0 --real-bytes 6 7 \
  --output rerun/real_high2.json

# Kalyna column 1, variable bytes (0,7)
python exhaustive_validation.py \
  --mode real --seed 20261119 --real-trials 4 --real-batch 128 \
  --real-column 1 --real-bytes 0 7 \
  --output rerun/real_col1.json

# Compare the fresh results with the saved results
python verify_results.py --rerun-dir rerun
```

The comparison ignores elapsed execution times but checks the saved experimental fields. The archived runs used NumPy 2.3.5; the reported candidate totals were also reproduced with NumPy 2.5.5.

For a short initial test:

```bash
python exhaustive_validation.py \
  --mode both --toy-trials 2 --real-trials 1 \
  --real-batch 128 --output smoke.json
```

The command-line options can be listed with `python exhaustive_validation.py --help`.

## 5. Results

| Experiment | Trials | Candidate evaluations | Correct key retained | Wrong survivors after first / both multisets |
|---|---:|---:|---:|---:|
| 16-bit model, complete terminal-key space | 256 | 16,777,216 | 256/256 | 1,974 / 772 |
| Kalyna-128/128, column 0, bytes `(0,7)` | 4 | 262,144 | 4/4 | 0 / 0 |
| Kalyna-128/128, column 0, bytes `(0,1)` | 4 | 262,144 | 4/4 | 0 / 0 |
| Kalyna-128/128, column 0, bytes `(6,7)` | 4 | 262,144 | 4/4 | 0 / 0 |
| Kalyna-128/128, column 1, bytes `(0,7)` | 4 | 262,144 | 4/4 | 0 / 0 |
| **Kalyna slice totals** | **16** | **1,048,576** | **16/16** | **0 / 0** |

The correct terminal-key candidate survived both multisets in every trial. In the 16-bit model, 772 incorrect candidates survived both tests, and all 256 trials had at least one such survivor. Thus, a balancedness test does not necessarily leave a unique candidate.

For Kalyna-128/128, no incorrect candidate survived in the tested slices. Of the 1,048,576 candidate evaluations, 1,048,560 were incorrect-candidate evaluations. The same candidate value may occur in more than one slice, so these are evaluation counts rather than necessarily distinct subkeys.

## 6. Scope and limitations

The 16-bit model is not standardized Kalyna. Its key schedule, state size, and S-box differ from the full cipher, so its survivor counts cannot be used directly to estimate full-Kalyna false-positive probabilities.

The real-Kalyna tests examine only two variable bytes of one 64-bit terminal-subkey column at a time. They therefore provide exhaustive evidence within the stated conditional slices, not an exhaustive search over all `2^64` column guesses or all `2^128` master keys. The experiments validate the three-round Kalyna-128/128 column-filtering setting (Algorithm 1), not exhaustive filtering for Algorithms 2–4 or all five Kalyna variants.

The scripts report integral balancedness and retention or rejection of round-subkey candidates. They do not establish unique master-key recovery. The other reduced-round configurations are implemented in the 15 validation scripts in the repository's variant directories.
