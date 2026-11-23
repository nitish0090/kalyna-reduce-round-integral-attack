#!/usr/bin/env python3
"""Exhaustive reduced-size terminal-subkey filtering and real-Kalyna key slices.

Two explicitly distinct experiments:
(1) TOY: exhaustive ALL 2^16 terminal keys of a Kalyna-like 16-bit SPN,
    with 2x8-bit columns, 4-bit bijective S-boxes, 2x2 MDS columns over
    GF(16), ShiftRows, XOR internal keys, and modular 2^8 whitening.
(2) REAL: exhaustive 2^k candidates in an explicitly restricted k-bit
    subspace of one genuine Kalyna-128/128 64-bit terminal-key column,
    keeping its remaining 64-k key bits at the correct values.

A toy-model experiment is NOT a cryptanalytic claim about Kalyna itself.
Exhaustive enumeration of a 16-bit subspace is NOT a complete 2^64 search.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import time
import numpy as np

S = np.array([12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2], dtype=np.uint8)
SIN = np.argsort(S).astype(np.uint8)


def gfmul(a: int, b: int) -> int:
    v = 0
    for _ in range(4):
        if b & 1:
            v ^= a
        b >>= 1
        a <<= 1
        if a & 16:
            a ^= 0x13
    return v


GF16 = np.array([[gfmul(i, j) for j in range(16)] for i in range(16)], dtype=np.uint8)
INV5 = next(i for i in range(1, 16) if gfmul(5, i) == 1)
M = np.array([[1, 2], [2, 1]], dtype=np.uint8)
IM = np.array([[INV5, gfmul(2, INV5)], [gfmul(2, INV5), INV5]], dtype=np.uint8)
SHIFT = [0, 3, 2, 1]  # move row1 between the two 2-nibble columns


def mix(x: np.ndarray, inverse: bool = False) -> np.ndarray:
    a = IM if inverse else M
    x = np.asarray(x, dtype=np.uint8)
    y = np.empty_like(x)
    for c in (0, 2):
        y[..., c] = GF16[a[0, 0], x[..., c]] ^ GF16[a[0, 1], x[..., c + 1]]
        y[..., c + 1] = GF16[a[1, 0], x[..., c]] ^ GF16[a[1, 1], x[..., c + 1]]
    return y


def fwd(x: np.ndarray) -> np.ndarray:
    return mix(S[np.asarray(x, dtype=np.uint8)][..., SHIFT])


def inv(x: np.ndarray) -> np.ndarray:
    return SIN[mix(x, inverse=True)[..., SHIFT]]


def add_whitening(x: np.ndarray, k: np.ndarray, subtract: bool = False) -> np.ndarray:
    x, k = np.broadcast_arrays(np.asarray(x, np.uint8), np.asarray(k, np.uint8))
    y = np.empty_like(x)
    for c in (0, 2):
        a = x[..., c].astype(np.uint16) | (x[..., c+1].astype(np.uint16) << 4)
        b = k[..., c].astype(np.uint16) | (k[..., c+1].astype(np.uint16) << 4)
        t = ((a-b) if subtract else (a+b)) & 255
        y[..., c] = (t & 15).astype(np.uint8)
        y[..., c+1] = (t >> 4).astype(np.uint8)
    return y


def toy_encrypt(p: np.ndarray, keys: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    x = add_whitening(p, keys[0])
    x = fwd(x) ^ keys[1]
    x2 = fwd(x) ^ keys[2]
    return add_whitening(fwd(x2), keys[3]), x2


def toy_structures(rng: np.random.Generator) -> tuple[np.ndarray, np.ndarray]:
    const = rng.integers(0, 16, 4, dtype=np.uint8)
    const[1] = 0
    p1 = np.broadcast_to(const, (16, 4)).copy()
    p1[:, 1] = np.arange(16, dtype=np.uint8)  # highest nibble col 0
    p2 = p1.copy()
    p2[:, 2] ^= 1  # a fixed change in inactive column, not key-dependent
    assert len(set(map(bytes, p1))) == len(set(map(bytes, p2))) == 16
    assert not set(map(bytes, p1)) & set(map(bytes, p2))
    return p1, p2


def toy_keys_from_ids(ids: np.ndarray) -> np.ndarray:
    v = np.asarray(ids, np.uint32)
    return np.stack([((v >> (4*j)) & 15).astype(np.uint8) for j in range(4)], axis=-1)


def toy_trial(rng: np.random.Generator, batch: int, index: int) -> dict:
    keys = rng.integers(0, 16, (4, 4), dtype=np.uint8)
    pt1, pt2 = toy_structures(rng)
    ct1, x1 = toy_encrypt(pt1, keys)
    ct2, x2 = toy_encrypt(pt2, keys)
    if not np.all(np.bitwise_xor.reduce(x1, axis=0) == 0) or not np.all(np.bitwise_xor.reduce(x2, axis=0) == 0):
        raise AssertionError("Expected two-round toy distinguisher does not hold")
    true_id = sum(int(keys[3, j]) << (4*j) for j in range(4))
    first = 0
    both = 0
    true_seen_first = False
    true_seen_both = False
    false_examples = []
    structured_wrong_first = 0
    structured_wrong_both = 0
    # Hamming-distance-1 *bit* neighborhood of terminal key
    neighbor = {true_id ^ (1 << i) for i in range(16)}
    for start in range(0, 1 << 16, batch):
        ids = np.arange(start, min(start+batch, 1 << 16), dtype=np.uint32)
        cand = toy_keys_from_ids(ids)
        recovered1 = inv(add_whitening(ct1[None, :, :], cand[:, None, :], subtract=True))
        ok1 = np.all(np.bitwise_xor.reduce(recovered1, axis=1) == 0, axis=1)
        n1 = int(np.count_nonzero(ok1)); first += n1
        pass_ids = ids[ok1]
        if len(pass_ids):
            recovered2 = inv(add_whitening(ct2[None, :, :], cand[ok1, None, :], subtract=True))
            ok2 = np.all(np.bitwise_xor.reduce(recovered2, axis=1) == 0, axis=1)
            pass_both = pass_ids[ok2]
            both += len(pass_both)
            true_seen_both |= bool(np.any(pass_both == true_id))
            false_examples.extend(int(v) for v in pass_both if int(v) != true_id and len(false_examples) < 10)
            structured_wrong_both += sum(int(v) in neighbor for v in pass_both)
        true_seen_first |= bool(np.any(pass_ids == true_id))
        structured_wrong_first += sum(int(v) in neighbor for v in pass_ids)
    if not true_seen_first or not true_seen_both:
        raise AssertionError("The true terminal subkey was rejected in exhaustive toy test")
    return dict(trial=index, true_terminal_key=f"{true_id:04x}", tested=65536,
                first=first, both=both, wrong_first=first-1, wrong_both=both-1,
                one_bit_wrong_tested=16,
                one_bit_wrong_first=structured_wrong_first,
                one_bit_wrong_both=structured_wrong_both,
                example_wrong_survivors=[f"{v:04x}" for v in false_examples])


def self_test_toy(rng):
    for _ in range(80):
        x = rng.integers(0,16,size=(8,4),dtype=np.uint8)
        k = rng.integers(0,16,size=(4,),dtype=np.uint8)
        assert np.array_equal(inv(fwd(x)), x)
        assert np.array_equal(add_whitening(add_whitening(x, k), k, True), x)
        assert np.array_equal(add_whitening(add_whitening(x, k, True), k), x)
    # Each nonzero 1x1 entry and all 2x2 matrix minors are nonsingular.
    assert all(int(v) != 0 for v in M.flat)
    assert gfmul(int(M[0, 0]), int(M[1, 1])) ^ gfmul(int(M[0, 1]), int(M[1, 0]))


def run_toy(args):
    rng = np.random.default_rng(args.seed)
    self_test_toy(rng)
    start = time.time()
    trials = [toy_trial(rng, args.batch, i) for i in range(args.toy_trials)]
    out = dict(type="toy_16bit_exhaustive_terminal_key",
               cipher="16-bit Kalyna-like SPN; two 8-bit columns, 4-bit S-box, GF(16) MDS, 2 internal rounds plus modular terminal whitening",
               experimental_scope="Exhaustive all 65536 terminal keys per trial; toy cipher, NOT standardized Kalyna",
               seed=args.seed, trials=args.toy_trials,
               keys_tested=sum(t['tested'] for t in trials),
               incorrect_keys_tested=sum(t['tested']-1 for t in trials),
               incorrect_survived_first=sum(t['wrong_first'] for t in trials),
               incorrect_survived_both=sum(t['wrong_both'] for t in trials),
               one_bit_wrong_tested=sum(t['one_bit_wrong_tested'] for t in trials),
               one_bit_wrong_survived_first=sum(t['one_bit_wrong_first'] for t in trials),
               one_bit_wrong_survived_both=sum(t['one_bit_wrong_both'] for t in trials),
               correct_retained=args.toy_trials,
               trials_with_nonunique_survivors=sum(t['wrong_both']>0 for t in trials),
               seconds=round(time.time()-start,3), per_trial=trials)
    return out


def import_real(path: Path):
    spec = importlib.util.spec_from_file_location('real_kalyna_reference', str(path))
    if spec is None or spec.loader is None:
        raise ValueError("Unable to import Kalyna reference")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def one_real_trial(args, trial_number: int):
    reference = Path(args.reference)
    if not reference.is_file():
        raise FileNotFoundError(f"Missing Kalyna reference module at {reference}. See README.md")
    k = import_real(reference)
    rng = np.random.default_rng(args.seed + 1 + trial_number)
    keys = k.expand_key(rng.integers(0, 256, 16, dtype=np.uint8))
    pts, _offset, _base = k.two_multisets(rng)
    cts = [k.encrypt(p, keys, rounds=3) for p in pts]
    for pt in pts:
        if not np.all(k.xorsum(k.get_internal_states(pt, keys)[2]) == 0):
            raise AssertionError('True Kalyna 2-round balance failed')
    col = args.real_column
    b0, b1 = args.real_bytes
    true_col = np.array(keys[3,8*col:8*col+8],dtype=np.uint8)
    tested = 0
    first = 0
    both = 0
    true_retained = False
    sample_false=[]
    t0=time.time()
    for start in range(0, 65536, args.real_batch):
        ids = np.arange(start, min(start+args.real_batch,65536), dtype=np.uint32)
        guesses = np.broadcast_to(true_col, (len(ids),8)).copy()
        guesses[:,b0] = (ids & 255).astype(np.uint8)
        guesses[:,b1] = ((ids >> 8)&255).astype(np.uint8)
        s1 = k.col_inversion_sums(cts[0][:,8*col:8*col+8],guesses)
        ok1 = np.all(s1==0,axis=1)
        first += int(np.count_nonzero(ok1))
        if np.any(ok1):
            s2 = k.col_inversion_sums(cts[1][:,8*col:8*col+8],guesses[ok1])
            ok2 = np.all(s2==0,axis=1)
            passed = guesses[ok1][ok2]
            both += len(passed)
            true_retained |= bool(np.any(np.all(passed==true_col,axis=1)))
            sample_false.extend(g.tobytes().hex() for g in passed if not np.array_equal(g,true_col))
        tested += len(ids)
    if tested != 65536 or not true_retained:
        raise AssertionError("Real Kalyna exhaustive subspace scan not complete or true key rejected")
    return dict(type="real_Kalyna128_128_terminal_column_16bit_subspace",
                reference_sha256=hashlib.sha256(reference.read_bytes()).hexdigest(),
                experimental_scope=("Exhaustive ALL 2^16 candidate values in the selected two-byte "
                                    "slice of one 64-bit terminal-key column; OTHER SIX BYTES are FIXED "
                                    "at their TRUE values, not a 2^64 exhaustive search"),
                underlying_integral="2-round exact integral, 2x256 chosen plaintexts, 3-round target",
                seed=args.seed + 1 + trial_number, trial=trial_number, column=col, positions=[b0,b1],
                correct_64bit_column_hex=true_col.tobytes().hex(),
                tested=65536, incorrect_tested=65535,
                incorrect_survived_first=first-1, incorrect_survived_both=both-1,
                correct_retained=true_retained,
                additional_wrong_survivors=sample_false[:20],
                seconds=round(time.time()-t0,3))


def run_real(args):
    per_trial = [one_real_trial(args, i) for i in range(args.real_trials)]
    return dict(type='real_Kalyna128_128_16bit_key_subspace_exhaustive',
                experimental_scope='For each of several genuine-master-key trials, exhaustive 2^16 values of two selected key bytes; six other bytes of the 64-bit column are held at the TRUE values; NOT full 2^64 exhaustive search',
                trials=args.real_trials,
                tested_per_trial=65536,
                total_tested=65536*args.real_trials,
                incorrect_total_tested=65535*args.real_trials,
                correct_retained=sum(r['correct_retained'] for r in per_trial),
                wrong_survived_first=sum(r['incorrect_survived_first'] for r in per_trial),
                wrong_survived_both=sum(r['incorrect_survived_both'] for r in per_trial),
                per_trial=per_trial)


def main():
    p=argparse.ArgumentParser(description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument('--mode',choices=['toy','real','both'],default='both')
    p.add_argument('--seed',type=int,default=20261119)
    p.add_argument('--toy-trials',type=int,default=20)
    p.add_argument('--batch',type=int,default=2048,help='Toy exhaustive 16-bit-key batch size')
    p.add_argument('--reference',default=str(Path(__file__).with_name('kalyna_reference.py')))
    p.add_argument('--real-batch',type=int,default=64,help='Real 16-bit key-slice batch size')
    p.add_argument('--real-trials',type=int,default=4,help='Independent genuine-master-key real trials')
    p.add_argument('--real-column',type=int,choices=[0,1],default=0)
    p.add_argument('--real-bytes',type=int,nargs=2,default=(0,7),metavar=('B0','B1'),
                   help='Two differing key bytes within the selected 8-byte column')
    p.add_argument('--output',default='kalyna_exhaustive_results.json')
    args=p.parse_args()
    if not (0 < args.toy_trials < 10000) or args.batch < 1 or args.real_batch < 1 or args.real_trials < 1:
        p.error('Invalid trials or batch size')
    if len(set(args.real_bytes))!=2 or any(not 0 <= x < 8 for x in args.real_bytes):
        p.error('--real-bytes requires distinct indices in range 0..7')
    report={"script":"exhaustive_validation.py","model_statement":"Toy model and actual Kalyna are DIFFERENT experiments"}
    if args.mode in ('toy','both'):
        report['toy']=run_toy(args)
        x=report['toy']
        print(f"TOY: {x['trials']} trials x 65,536 ALL terminal keys; correct {x['correct_retained']}/{x['trials']}; "
              f"wrong survivors first={x['incorrect_survived_first']}, both={x['incorrect_survived_both']}; "
              f"nonunique trials={x['trials_with_nonunique_survivors']}",flush=True)
    if args.mode in ('real','both'):
        report['real']=run_real(args)
        x=report['real']
        print(f"REAL: {x['trials']} independent genuine-key trials x 65,536 keys in a specified 16-bit SLICE; "
              f"correct retained={x['correct_retained']}/{x['trials']}; wrong first={x['wrong_survived_first']}, "
              f"both={x['wrong_survived_both']}",flush=True)
    Path(args.output).write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
    print('Wrote:',args.output,flush=True)


if __name__ == '__main__':
    main()
