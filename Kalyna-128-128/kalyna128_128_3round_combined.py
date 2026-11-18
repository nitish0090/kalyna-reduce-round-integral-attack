#!/usr/bin/env python3
"""Kalyna-128/128 2-round integral and 3-round last-subkey filtering.

Single-file research validation for Sections 3.1 and 6, Table 2 and Algorithms 1-2.
Default: 1000 trials, independent genuine expanded Kalyna-128/128 master keys.
Each trial tests two disjoint complete 256-text chosen-plaintext multisets.

This is a test of (i) the 2-round internal balanced property and (ii) retention
of the true 64-bit terminal subkey columns after one-round partial decryption.
Wrong-column testing is sampled, including exhaustive 255 alternatives for the
MSB key byte. No exhaustive 2^64 search or complete master-key recovery.

The S-box, MDS matrix, core and key expansion are reused from the supplied,
reference-checked Kalyna-128 code. State is column-major; 64-bit words little endian.
"""
from __future__ import annotations

# ==============================================================
# PART I: Kalyna-128 primitives, test vectors, key schedule
# ==============================================================
import argparse
import csv
import hashlib
import importlib
import json
import os
from pathlib import Path
import platform
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
import numpy as np

SBOX = np.array([
    [168, 67, 95, 6, 107, 117, 108, 89, 113, 223, 135, 149, 23, 240, 216, 9, 109, 243, 29, 203, 201, 77, 44, 175, 121, 224, 151, 253, 111, 75, 69, 57, 62, 221, 163, 79, 180, 182, 154, 14, 31, 191, 21, 225, 73, 210, 147, 198, 146, 114, 158, 97, 209, 99, 250, 238, 244, 25, 213, 173, 88, 164, 187, 161, 220, 242, 131, 55, 66, 228, 122, 50, 156, 204, 171, 74, 143, 110, 4, 39, 46, 231, 226, 90, 150, 22, 35, 43, 194, 101, 102, 15, 188, 169, 71, 65, 52, 72, 252, 183, 106, 136, 165, 83, 134, 249, 91, 219, 56, 123, 195, 30, 34, 51, 36, 40, 54, 199, 178, 59, 142, 119, 186, 245, 20, 159, 8, 85, 155, 76, 254, 96, 92, 218, 24, 70, 205, 125, 33, 176, 63, 27, 137, 255, 235, 132, 105, 58, 157, 215, 211, 112, 103, 64, 181, 222, 93, 48, 145, 177, 120, 17, 1, 229, 0, 104, 152, 160, 197, 2, 166, 116, 45, 11, 162, 118, 179, 190, 206, 189, 174, 233, 138, 49, 28, 236, 241, 153, 148, 170, 246, 38, 47, 239, 232, 140, 53, 3, 212, 127, 251, 5, 193, 94, 144, 32, 61, 130, 247, 234, 10, 13, 126, 248, 80, 26, 196, 7, 87, 184, 60, 98, 227, 200, 172, 82, 100, 16, 208, 217, 19, 12, 18, 41, 81, 185, 207, 214, 115, 141, 129, 84, 192, 237, 78, 68, 167, 42, 133, 37, 230, 202, 124, 139, 86, 128],
    [206, 187, 235, 146, 234, 203, 19, 193, 233, 58, 214, 178, 210, 144, 23, 248, 66, 21, 86, 180, 101, 28, 136, 67, 197, 92, 54, 186, 245, 87, 103, 141, 49, 246, 100, 88, 158, 244, 34, 170, 117, 15, 2, 177, 223, 109, 115, 77, 124, 38, 46, 247, 8, 93, 68, 62, 159, 20, 200, 174, 84, 16, 216, 188, 26, 107, 105, 243, 189, 51, 171, 250, 209, 155, 104, 78, 22, 149, 145, 238, 76, 99, 142, 91, 204, 60, 25, 161, 129, 73, 123, 217, 111, 55, 96, 202, 231, 43, 72, 253, 150, 69, 252, 65, 18, 13, 121, 229, 137, 140, 227, 32, 48, 220, 183, 108, 74, 181, 63, 151, 212, 98, 45, 6, 164, 165, 131, 95, 42, 218, 201, 0, 126, 162, 85, 191, 17, 213, 156, 207, 14, 10, 61, 81, 125, 147, 27, 254, 196, 71, 9, 134, 11, 143, 157, 106, 7, 185, 176, 152, 24, 50, 113, 75, 239, 59, 112, 160, 228, 64, 255, 195, 169, 230, 120, 249, 139, 70, 128, 30, 56, 225, 184, 168, 224, 12, 35, 118, 29, 37, 36, 5, 241, 110, 148, 40, 154, 132, 232, 163, 79, 119, 211, 133, 226, 82, 242, 130, 80, 122, 47, 116, 83, 179, 97, 175, 57, 53, 222, 205, 31, 153, 172, 173, 114, 44, 221, 208, 135, 190, 94, 166, 236, 4, 198, 3, 52, 251, 219, 89, 182, 194, 1, 240, 90, 237, 167, 102, 33, 127, 138, 39, 199, 192, 41, 215],
    [147, 217, 154, 181, 152, 34, 69, 252, 186, 106, 223, 2, 159, 220, 81, 89, 74, 23, 43, 194, 148, 244, 187, 163, 98, 228, 113, 212, 205, 112, 22, 225, 73, 60, 192, 216, 92, 155, 173, 133, 83, 161, 122, 200, 45, 224, 209, 114, 166, 44, 196, 227, 118, 120, 183, 180, 9, 59, 14, 65, 76, 222, 178, 144, 37, 165, 215, 3, 17, 0, 195, 46, 146, 239, 78, 18, 157, 125, 203, 53, 16, 213, 79, 158, 77, 169, 85, 198, 208, 123, 24, 151, 211, 54, 230, 72, 86, 129, 143, 119, 204, 156, 185, 226, 172, 184, 47, 21, 164, 124, 218, 56, 30, 11, 5, 214, 20, 110, 108, 126, 102, 253, 177, 229, 96, 175, 94, 51, 135, 201, 240, 93, 109, 63, 136, 141, 199, 247, 29, 233, 236, 237, 128, 41, 39, 207, 153, 168, 80, 15, 55, 36, 40, 48, 149, 210, 62, 91, 64, 131, 179, 105, 87, 31, 7, 28, 138, 188, 32, 235, 206, 142, 171, 238, 49, 162, 115, 249, 202, 58, 26, 251, 13, 193, 254, 250, 242, 111, 189, 150, 221, 67, 82, 182, 8, 243, 174, 190, 25, 137, 50, 38, 176, 234, 75, 100, 132, 130, 107, 245, 121, 191, 1, 95, 117, 99, 27, 35, 61, 104, 42, 101, 232, 145, 246, 255, 19, 88, 241, 71, 10, 127, 197, 167, 231, 97, 90, 6, 70, 68, 66, 4, 160, 219, 57, 134, 84, 170, 140, 52, 33, 139, 248, 12, 116, 103],
    [104, 141, 202, 77, 115, 75, 78, 42, 212, 82, 38, 179, 84, 30, 25, 31, 34, 3, 70, 61, 45, 74, 83, 131, 19, 138, 183, 213, 37, 121, 245, 189, 88, 47, 13, 2, 237, 81, 158, 17, 242, 62, 85, 94, 209, 22, 60, 102, 112, 93, 243, 69, 64, 204, 232, 148, 86, 8, 206, 26, 58, 210, 225, 223, 181, 56, 110, 14, 229, 244, 249, 134, 233, 79, 214, 133, 35, 207, 50, 153, 49, 20, 174, 238, 200, 72, 211, 48, 161, 146, 65, 177, 24, 196, 44, 113, 114, 68, 21, 253, 55, 190, 95, 170, 155, 136, 216, 171, 137, 156, 250, 96, 234, 188, 98, 12, 36, 166, 168, 236, 103, 32, 219, 124, 40, 221, 172, 91, 52, 126, 16, 241, 123, 143, 99, 160, 5, 154, 67, 119, 33, 191, 39, 9, 195, 159, 182, 215, 41, 194, 235, 192, 164, 139, 140, 29, 251, 255, 193, 178, 151, 46, 248, 101, 246, 117, 7, 4, 73, 51, 228, 217, 185, 208, 66, 199, 108, 144, 0, 142, 111, 80, 1, 197, 218, 71, 63, 205, 105, 162, 226, 122, 167, 198, 147, 15, 10, 6, 230, 43, 150, 163, 28, 175, 106, 18, 132, 57, 231, 176, 130, 247, 254, 157, 135, 92, 129, 53, 222, 180, 165, 252, 128, 239, 203, 187, 107, 118, 186, 90, 125, 120, 11, 149, 227, 173, 116, 152, 59, 54, 100, 109, 220, 240, 89, 169, 76, 23, 127, 145, 184, 201, 87, 27, 224, 97],
], dtype=np.uint8)
MDS = np.array([
    [1, 1, 5, 1, 8, 6, 7, 4],
    [4, 1, 1, 5, 1, 8, 6, 7],
    [7, 4, 1, 1, 5, 1, 8, 6],
    [6, 7, 4, 1, 1, 5, 1, 8],
    [8, 6, 7, 4, 1, 1, 5, 1],
    [1, 8, 6, 7, 4, 1, 1, 5],
    [5, 1, 8, 6, 7, 4, 1, 1],
    [1, 5, 1, 8, 6, 7, 4, 1],
], dtype=np.uint8)
IMDS = np.array([
    [173, 149, 118, 168, 47, 73, 215, 202],
    [202, 173, 149, 118, 168, 47, 73, 215],
    [215, 202, 173, 149, 118, 168, 47, 73],
    [73, 215, 202, 173, 149, 118, 168, 47],
    [47, 73, 215, 202, 173, 149, 118, 168],
    [168, 47, 73, 215, 202, 173, 149, 118],
    [118, 168, 47, 73, 215, 202, 173, 149],
    [149, 118, 168, 47, 73, 215, 202, 173],
], dtype=np.uint8)
INV_SBOX = np.argsort(SBOX, axis=1).astype(np.uint8)

def gf(a,b,poly=0x11d,bits=8):
    z=0
    for _ in range(bits):
        if b&1: z ^= a
        a <<= 1
        if a & (1<<bits): a ^= poly
        b >>= 1
    return z

# Complete GF(256) multiplication table, generated rather than imported.
GF = np.array([[gf(a,b) for b in range(256)] for a in range(256)],dtype=np.uint8)
SR = np.array([8*((c-r//4)%2)+r for c in range(2) for r in range(8)])

def asbytes(x):
    return np.frombuffer(x,dtype=np.uint8).copy() if isinstance(x,bytes) else np.asarray(x,dtype=np.uint8)

def mix(x,inverse=False):
    x=asbytes(x)
    if x.shape[-1] % 8: raise ValueError('Whole 64-bit columns required')
    a=x.reshape(x.shape[:-1]+(-1,8))
    mat=IMDS if inverse else MDS
    y=np.zeros_like(a)
    for r in range(8):
        for t in range(8): y[...,r] ^= GF[mat[r,t],a[...,t]]
    return y.reshape(x.shape)

def linear(x):
    return mix(asbytes(x)[...,SR])

def linear_inverse(x):
    return mix(x,True)[...,SR]  # For 128-bit blocks SR is self-inverse.

def F(x):
    x=asbytes(x)
    return linear(SBOX[np.arange(16)%4,x])

def Finv(x):
    y=linear_inverse(x)
    return INV_SBOX[np.arange(16)%4,y]

def add64(x,key,subtract=False):
    x,key=np.broadcast_arrays(asbytes(x),asbytes(key))
    if x.shape[-1]%8: raise ValueError('Whole 64-bit columns required')
    # Explicit byte carry/borrow: portable to big-endian hosts and any strides.
    a=x.reshape(x.shape[:-1]+(-1,8)).astype(np.int16)
    b=key.reshape(key.shape[:-1]+(-1,8)).astype(np.int16)
    y=np.empty_like(a,dtype=np.uint8)
    carry=np.zeros(a.shape[:-1],dtype=np.int16)
    for i in range(8):
        v=a[...,i]-b[...,i]-carry if subtract else a[...,i]+b[...,i]+carry
        y[...,i]=(v&255).astype(np.uint8)
        carry=(v<0).astype(np.int16) if subtract else v>>8
    return y.reshape(x.shape)

def sub64(x,key): return add64(x,key,True)

def odd_from_even(key):
    # Reference RotateLeft rotates the BYTE ARRAY left by 7 bytes.
    # This is a numeric right rotation of a little-endian 128-bit integer.
    return np.roll(asbytes(key),-7,axis=-1)

def even_from_odd(key): return np.roll(asbytes(key),7,axis=-1)

def expand_key(master):
    key=asbytes(master)
    if key.ndim!=1 or len(key) not in (16,32): raise ValueError('Master key must have 16 or 32 bytes')
    nr=10 if len(key)==16 else 14
    a=key[:16]; b=key[-16:]
    s=np.zeros(16,dtype=np.uint8); s[0]=2+len(key)//8+1
    kt=F(add64(F(F(add64(s,a))^b),a))
    keys=np.zeros((nr+1,16),dtype=np.uint8)
    initial=key.copy(); tmv=np.tile(np.array([1,0,1,0,1,0,1,0],dtype=np.uint8),2)
    rnd=0
    while True:
        for offset in range(0,len(key),16):
            tr=add64(kt,tmv)
            keys[rnd]=add64(F(F(add64(initial[offset:offset+16],tr))^tr),tr)
            if rnd==nr:
                for j in range(1,nr,2): keys[j]=odd_from_even(keys[j-1])
                return keys
            rnd+=2
            tmv=add64(tmv,tmv)
        initial=np.roll(initial,-8)

def internal(p,keys,rounds,pre=True):
    x=add64(p,keys[0]) if pre else asbytes(p).copy()
    for r in range(1,rounds+1): x=F(x)^keys[r]
    return x

def encrypt(p,keys,rounds=None,pre=True):
    rounds=len(keys)-1 if rounds is None else rounds
    if not 1<=rounds<len(keys): raise ValueError('Invalid target round count')
    x=internal(p,keys,rounds-1,pre)
    return add64(F(x),keys[rounds])

def decrypt(c,keys,rounds=None,pre=True):
    rounds=len(keys)-1 if rounds is None else rounds
    x=Finv(sub64(c,keys[rounds]))
    for r in range(rounds-1,0,-1): x=Finv(x^keys[r])
    return sub64(x,keys[0]) if pre else x

# ================================================================
# PART II — Exact 2R multiset and 3R column subkey filtering
# ================================================================

from concurrent.futures import ProcessPoolExecutor, wait, FIRST_COMPLETED
from itertools import product

VERSION = "1.0"
BYTE_VALUES = np.arange(256, dtype=np.uint8)
MSB_DIFF_MASK = 0xff << 56
MASK64 = (1 << 64) - 1
FAMILIES = ("uniform_random_64bit", "single_bit_xor", "all_255_MSB_byte_changes", "carry_and_modular_boundaries")


def require(predicate, message):
    if not bool(predicate):
        raise AssertionError(message)


def one_multiset(base: np.ndarray, offset: int):
    """{a xor x e7 : x=0..255}, with a[7]=0 and a[4]=offset."""
    a = np.asarray(base, dtype=np.uint8).copy()
    require(a.shape == (16,), 'base must be 16 bytes')
    a[7] = 0
    a[4] = offset
    p = np.broadcast_to(a, (256, 16)).copy()
    p[:, 7] = BYTE_VALUES
    require(np.unique(p, axis=0).shape[0] == 256, 'incorrect chosen plaintext structure')
    return p


def two_multisets(rng):
    a = rng.integers(0, 256, size=16, dtype=np.uint8)
    a[7] = 0
    other = int(rng.integers(1, 256))
    a0 = one_multiset(a, 0)
    a1 = one_multiset(a, other)
    require(not np.any(a0[:, 4]), 'first structure offset must be zero')
    require(np.all(a1[:, 4] == other), 'second structure offset mismatch')
    require(not np.any(np.isin(a0.view('V16'), a1.view('V16'))), 'multisets must be disjoint')
    return (a0, a1), other, a


def xorsum(state):
    return np.bitwise_xor.reduce(state, axis=0)


def properties(state):
    s = xorsum(state)
    res = []
    n = state.shape[0]
    for pos in range(16):
        freqs = np.bincount(state[:, pos], minlength=256)
        if np.count_nonzero(freqs) == 1: res.append('C')
        elif n % 256 == 0 and np.all(freqs == n // 256): res.append('A')
        elif s[pos] == 0: res.append('B')
        else: res.append('U')
    return ''.join(res)


def get_internal_states(p, keys):
    # X0: genuine prewhitening; X1 & X2 are XOR-keyed internal states.
    x0 = add64(p, keys[0])
    x1 = F(x0) ^ keys[1]
    x2 = F(x1) ^ keys[2]
    return x0, x1, x2


def verify_distinguisher(p, keys):
    """Independent marginal checks at X0/X1, exact bytewise XOR balance at X2."""
    x0, x1, x2 = get_internal_states(p, keys)
    require(np.array_equal(np.sort(x0[:, 7]), BYTE_VALUES), 'active byte not All after prewhitening')
    require(np.all(x0[:, :7] == x0[0, :7]), 'other first-column bytes not constant after PW')
    require(np.all(x0[:, 8:] == x0[0, 8:]), 'second column not constant after PW')
    require(np.all(x1[:, :8] == x1[0, :8]), 'first column not C after round 1')
    for i in range(8, 16):
        require(np.array_equal(np.sort(x1[:, i]), BYTE_VALUES), f'X1 byte {i} not All')
    sums = xorsum(x2)
    require(not np.any(sums), '2R internal-state XOR balance failed: '+sums.tobytes().hex())
    return (x0, x1, x2), {
        'round0_post_prewhitening': properties(x0),
        'round1': properties(x1),
        'round2': properties(x2),
        'round2_zero_xor_bytes': int(np.count_nonzero(sums == 0)),
        'round2_xor_sum_hex': sums.tobytes().hex(),
        'round2_internal_state_sha256': hashlib.sha256(x2.tobytes()).hexdigest(),
    }


def col_inversion_sums(ct_col, guesses):
    """Algorithm 1: terminal subtraction -> MC^-1 -> SB^-1, per 64-bit column.

    ct_col is N x 8, guesses G x 8.  The returned G x 8 byte sums
    correspond to the source positions I_j under inverse ShiftRows, without
    incorrectly applying inverse ShiftRows within an isolated column.
    """
    guess_array = np.asarray(guesses, dtype=np.uint8).reshape(-1, 8)
    if len(guess_array) == 0:
        return np.empty((0, 8), dtype=np.uint8)
    z = sub64(ct_col[None, :, :], guess_array[:, None, :])
    v = mix(z, inverse=True)
    previous_shifted = INV_SBOX[np.arange(8) % 4, v]
    return np.bitwise_xor.reduce(previous_shifted, axis=1)


def check_column_correct(cts, key, column, original_x2s):
    """Cross-check partial and full inversion, including modular borrows."""
    guess = keyslice(key, column)
    sr_positions = SR[8 * column : 8 * (column + 1)]
    for ms, ct in enumerate(cts):
        ss = col_inversion_sums(ct[:, column * 8 : (column + 1) * 8], guess[None, :])
        require(np.all(ss == 0), 'true 64-bit terminal key failed balance')
        full = Finv(sub64(ct, key))
        require(np.array_equal(full, original_x2s[ms]), 'correct full inverse not X2')
        shifted = full[:, sr_positions]
        z = sub64(ct[:, column * 8 : (column + 1) * 8], guess)
        got = INV_SBOX[np.arange(8) % 4, mix(z, inverse=True)]
        require(np.array_equal(got, shifted), 'column-only inverse disagrees with full-state inverse')
    return [int(x) for x in sr_positions]


def keyslice(key, column):
    return np.asarray(key[8 * column:8 * (column + 1)], dtype=np.uint8)


def key_from_integer(n):
    return (n & MASK64).to_bytes(8, 'little')


def wrong_families(true_key, rng, random_count, enable_msb):
    genuine = bytes(true_key)
    x = int.from_bytes(genuine, 'little')
    randoms = set()
    while len(randoms) < random_count:
        trial = bytes(rng.integers(0, 256, 8, dtype=np.uint8))
        if trial != genuine: randoms.add(trial)
    onebit = {key_from_integer(x ^ (1 << i)) for i in range(64)}
    msb = {genuine[:7] + bytes([v]) for v in range(256) if v != genuine[7]} if enable_msb else set()
    boundaries = {key_from_integer(v) for v in (
        0, MASK64, x + 1, x - 1, x + (1 << 63), x - (1 << 63),
        x ^ (1 << 63), x + (1 << 56), x - (1 << 56),
        x + 0xff, x - 0xff, x ^ 0xff, x ^ 0xff00,
        x ^ 0xffff, x ^ 0xffffffff, x ^ (MASK64 >> 1),
    )}
    out = {
        'uniform_random_64bit': randoms,
        'single_bit_xor': onebit,
        'all_255_MSB_byte_changes': msb,
        'carry_and_modular_boundaries': boundaries,
    }
    for members in out.values():
        members.discard(genuine)
    return out


def test_wrong_columns(cts, col, families, chunk_size):
    """Deduplicate across families, and early-reject after first multiset.

    Do not interpret a sample estimate as the probability for arbitrary keys.
    """
    union = sorted(set().union(*families.values()))
    pass_first, pass_both = set(), set()
    for start in range(0, len(union), chunk_size):
        chunk = union[start:start+chunk_size]
        guesses = np.frombuffer(b''.join(chunk), dtype=np.uint8).reshape(-1, 8)
        z1 = col_inversion_sums(cts[0][:, 8*col : 8*col+8], guesses)
        idx = np.flatnonzero(np.all(z1 == 0, axis=1))
        passed = [chunk[int(i)] for i in idx]
        pass_first.update(passed)
        if passed:
            z2 = col_inversion_sums(cts[1][:, 8*col : 8*col+8],
                     np.frombuffer(b''.join(passed), dtype=np.uint8).reshape(-1,8))
            pass_both.update(v for v,good in zip(passed,np.all(z2==0, axis=1)) if good)
    breakdown = {}
    for fam in FAMILIES:
        candidate_set = families[fam]
        breakdown[fam] = {
            'tested': len(candidate_set),
            'survive_first_multiset': len(candidate_set & pass_first),
            'survive_both_multisets': len(candidate_set & pass_both),
            'wrong_survivor_hex': [k.hex() for k in sorted(candidate_set & pass_both)],
        }
    return breakdown, {
        'unique_wrong_candidates_tested': len(union),
        'unique_wrong_surviving_first_multiset': len(pass_first),
        'unique_wrong_surviving_both_multisets': len(pass_both),
        'all_unique_wrong_survivor_hex': [k.hex() for k in sorted(pass_both)],
        'union_sha256': hashlib.sha256(b''.join(union)).hexdigest(),
    }


def deterministic_rng(seed, trial):
    digest = hashlib.sha256(f'kalyna128_128_3R|{seed}|{trial}'.encode('ascii')).digest()
    return np.random.default_rng(int.from_bytes(digest[:16], 'little'))


def sample_vectors(p, states, ct):
    x0,x1,x2 = states
    return [dict(x=x, plaintext=p[x].tobytes().hex(),
                 post_prewhitening=x0[x].tobytes().hex(),
                 state_after_round1=x1[x].tobytes().hex(),
                 state_after_round2=x2[x].tobytes().hex(),
                 ciphertext_3round=ct[x].tobytes().hex()) for x in (0,1,128,255)]


def one_trial(tidx, cfg):
    rng = deterministic_rng(cfg['seed'], tidx)
    master = rng.integers(0, 256, 16, dtype=np.uint8)
    keys = expand_key(master)
    require(keys.shape == (11,16), 'genuine Kalyna 128/128 key schedule must have 11 subkeys')
    require(np.array_equal(keys[3], odd_from_even(keys[2])), 'odd K3 does not derive from K2')
    ps, offset, base = two_multisets(rng)
    evidence=[]
    states_list=[]
    ctsets=[]
    for k,p in enumerate(ps):
        states,dist = verify_distinguisher(p,keys)
        states_list.append(states)
        ciphertexts = add64(F(states[-1]), keys[3])
        require(np.array_equal(ciphertexts, encrypt(p,keys,rounds=3)), '3R ciphertext mismatch')
        ctsets.append(ciphertexts)
        dist['multiset'] = k
        dist['offset_byte4'] = 0 if k == 0 else offset
        dist['plaintext_sha256'] = hashlib.sha256(p.tobytes()).hexdigest()
        dist['ciphertext_sha256'] = hashlib.sha256(ciphertexts.tobytes()).hexdigest()
        dist['terminal_ciphertext_xor_sum_hex'] = xorsum(ciphertexts).tobytes().hex()
        evidence.append(dist)
    attack=[]
    count_full_candidates=1
    for col in (0,1):
        orig_positions=check_column_correct(ctsets, keys[3], col,[s[-1] for s in states_list])
        real=keyslice(keys[3], col)
        families=wrong_families(real, rng, cfg['random_wrong'], cfg['full_msb'])
        bd, dedup=test_wrong_columns(ctsets,col,families,cfg['chunk_size'])
        count_full_candidates *= (1+dedup['unique_wrong_surviving_both_multisets'])
        attack.append({
          'column':col,
          'index_set_Ij':orig_positions,
          'true_terminal_64bit_key_hex':real.tobytes().hex(),
          'true_candidate_survives_multiset1':True,
          'true_candidate_survives_multiset2':True,
          'wrong_candidate_families':bd,
          'deduplicated_wrong_testing':dedup,
        })
    reconstruct=even_from_odd(keys[3])
    require(np.array_equal(reconstruct,keys[2]), 'Algorithm 2 derived K2 differs from true key')
    # Algorithm 1 gives column-survivor sets. Algorithm 2 derives the preceding
    # even subkey for EVERY complete K3 candidate, not only the known true one.
    # Retain nonunique survivors, without claiming master-key recovery.
    column_sets = []
    for col in attack:
        colno=col['column']
        found = {bytes(keyslice(keys[3],colno))}
        found.update(bytes.fromhex(x) for x in col['deduplicated_wrong_testing']['all_unique_wrong_survivor_hex'])
        column_sets.append(sorted(found))
    require(count_full_candidates == len(column_sets[0])*len(column_sets[1]),
            'Cartesian candidate count mismatch')
    full_candidate_tuples = []
    if count_full_candidates <= 512:
        for col0,col1 in product(*column_sets):
            candidate3=np.frombuffer(col0+col1,dtype=np.uint8).copy()
            candidate2=even_from_odd(candidate3)
            full_candidate_tuples.append({
                'K3_hex':candidate3.tobytes().hex(),
                'derived_K2_hex':candidate2.tobytes().hex(),
                'is_true_K3':bool(np.array_equal(candidate3,keys[3])),
            })
        require(any(x['is_true_K3'] for x in full_candidate_tuples),
                'correct full K3 absent from candidate list')
    res = {
      'trial':tidx, 'status':'PASS', 'variant':'Kalyna-128/128',
      'master_key_hex':master.tobytes().hex(),
      'keys_K0_to_K3_hex':[k.tobytes().hex() for k in keys[:4]],
      'plaintext_fixed_base_hex':base.tobytes().hex(),
      'second_multiset_offset_byte4':offset,
      'distinguisher': {'rounds':2,'prewhitening':True,'plaintexts_per_multiset':256,
                         'two_multisets_are_disjoint':True,
                         'results':evidence, 'all_16_byte_sums_zero':True},
      'key_filtering': {'target_rounds':3,'plaintexts_total':512,
                        'terminal_operation':'column-wise modular addition mod 2^64',
                        'correct_K3_terminal_128bit_hex':keys[3].tobytes().hex(),
                        'derived_K2_128bit_hex':reconstruct.tobytes().hex(),
                        'correct_K3_in_tested_candidate_cartesian_product':True,
                        'observed_full_K3_combinations_in_tested_product':count_full_candidates,
                        'enumerated_K3_and_derived_K2_tuples_if_at_most_512':full_candidate_tuples,
                        'large_product_note':None if count_full_candidates<=512 else
                             'Candidate product too large to enumerate here; exact column survivor sets retained.',
                        'columns':attack,
                        'does_not_claim_master_key_recovery':True},
    }
    if tidx == 0:
        res['reproducible_test_vectors'] = [
          {'multiset':j,'samples':sample_vectors(ps[j],states_list[j],ctsets[j])} for j in (0,1)]
    return res


def selftest():
    # Known-answer vectors from the uploaded reference-checked cipher core.
    for size, expected in [(16,'81bf1c7d779bac20e1c9ea39b4d2ad06'),
                           (32,'58ec3e091000158a1148f7166f334f14')]:
        master = np.arange(size,dtype=np.uint8)
        pt = np.arange(size, size+16,dtype=np.uint8)
        key = expand_key(master)
        got = encrypt(pt,key).tobytes().hex()
        require(got == expected, 'Kalyna official encryption KAT failed: '+str(size))
        require(np.array_equal(decrypt(encrypt(pt,key),key),pt), 'full cipher decrypt KAT failed')
    # Two published decryption known-answer vectors, also from original code.
    for size,ct,expected in [(16,bytes(range(31,15,-1)),'7291ef2b470cc7846f09c2303973dad7'),
                             (32,bytes(range(47,31,-1)),'f36db456cefddfe1b45b5f7030cad996')]:
        master = np.arange(size-1,-1,-1,dtype=np.uint8)
        got = decrypt(np.frombuffer(ct,dtype=np.uint8), expand_key(master)).tobytes().hex()
        require(got==expected,'Kalyna official decryption KAT failed: '+str(size))
    rng=np.random.default_rng(0x8122)
    for iteration in range(24):
        state=rng.integers(0,256,(3,16),dtype=np.uint8)
        require(np.array_equal(Finv(F(state)),state),'F inverse failed')
        key=rng.integers(0,256,(3,16),dtype=np.uint8)
        z=add64(state,key)
        require(np.array_equal(sub64(z,key),state),'modular subtract inverse failed')
        for j in (0,1):
            b=int.from_bytes(state[0,8*j:8*j+8].tobytes(),'little')
            k=int.from_bytes(key[0,8*j:8*j+8].tobytes(),'little')
            require(z[0,8*j:8*j+8].tobytes() == ((b+k)&MASK64).to_bytes(8,'little'),
                    'modular carry arithmetic wrong')
        ct=add64(F(state),key[0])
        for col in (0,1):
            z=sub64(ct[:,8*col:8*col+8],key[0,8*col:8*col+8])
            reduced=INV_SBOX[np.arange(8)%4,mix(z,inverse=True)]
            full=Finv(sub64(ct,key[0]))[:,SR[8*col:8*col+8]]
            require(np.array_equal(reduced,full),'column inverse indexing mismatch')
            # Validate the *wrong* guess path too, not just correct-key behavior.
            altered=key[0].copy()
            altered[8*col:8*col+8] ^= np.array([1,0,0,0,0,0,0,128],dtype=np.uint8)
            partial=col_inversion_sums(ct[:,8*col:8*col+8],altered[8*col:8*col+8][None,:])[0]
            wrongfull=Finv(sub64(ct,altered))
            require(np.array_equal(partial,xorsum(wrongfull[:,SR[8*col:8*col+8]])),
                    'wrong candidate partial inverse mismatch')
    return {'official_encryption_known_answer_vectors':2,
            'official_decryption_known_answer_vectors':2,
            'round_inverse_random_tests':24,
            'modular_arithmetic_crosschecks':48,
            'correct_and_wrong_partial_column_crosschecks':96,
            'status':'PASS'}


def atomic_json(p,d):
    p=Path(p);p.parent.mkdir(parents=True,exist_ok=True)
    temp=p.with_suffix(p.suffix+'.tmp')
    temp.write_text(json.dumps(d,sort_keys=True,indent=2)+'\n',encoding='utf-8')
    os.replace(temp,p)


def summarize(outdir, cfg):
    alltrials=[json.loads((outdir/'trials'/f'{i:05d}.json').read_text()) for i in range(cfg['trials'])]
    families={}
    total=0
    for case in alltrials:
        require(case['status']=='PASS','bad saved trial')
        require(all(x['round2_zero_xor_bytes']==16 for x in case['distinguisher']['results']), 'balance failed')
        for col in case['key_filtering']['columns']:
            total+=1
            for fam,stat in col['wrong_candidate_families'].items():
                key=(col['column'],fam)
                x=families.setdefault(key,{'column':col['column'],'family':fam,
                    'evaluations':0,'survivors_after_first':0,'survivors_after_both':0})
                x['evaluations'] += stat['tested']
                x['survivors_after_first'] += stat['survive_first_multiset']
                x['survivors_after_both'] += stat['survive_both_multisets']
    rows=sorted(families.values(),key=lambda r:(r['column'],r['family']))
    with (outdir/'wrong_key_survivors.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=['column','family','evaluations','survivors_after_first','survivors_after_both'])
        w.writeheader();w.writerows(rows)
    report = {
        'variant':'Kalyna-128/128','trials_completed':len(alltrials),
        'trials_requested':cfg['trials'],
        'genuine_master_keys_tested':cfg['trials'],
        'key_model':'genuine 128-bit master key expanded by Kalyna key schedule',
        'distinguisher':{'rounds':2,'plaintexts_per_multiset':256,
                         'disjoint_multisets_per_trial':2,
                         'full_multisets_verified':cfg['trials']*2,
                         'balanced_byte_positions':16,
                         'positive_trials':cfg['trials'],'status':'PASS'},
        'key_filtering':{'target_rounds':3,'chosen_plaintexts_per_trial':512,
                         'true_terminal_64bit_column_candidates_retained':2*cfg['trials'],
                         'true_K3_128bit_retained_all_trials':True,
                         'true_K2_derived_by_odd_round_rotation_all_trials':True,
                         'per_family_counts':rows,
                         'false_candidate_note':'Wrong candidates tested are samples and structured slices, not exhaustive 2^64. Families can overlap; counts are evaluations.',
                         'full_master_key_recovery_claimed':False},
        'results_are_conditioned_on_sampled_guesses':True,
        'nominal_work_from_paper':'2^74 64-bit column partial-decryption operations (not measured or fully executed)',
        'result':'PASS',
    }
    atomic_json(outdir/'summary.json',report)
    examples=alltrials[0]['reproducible_test_vectors']
    atomic_json(outdir/'reproducible_test_vectors.json',{
        'trial_0_master_key_hex':alltrials[0]['master_key_hex'],
        'trial_0_keys_K0_to_K3':alltrials[0]['keys_K0_to_K3_hex'],
        'vectors':examples})
    r=[]
    r += ['# Kalyna-128/128: 2-round distinguisher and 3-round last-subkey filtering','']
    r += ['## Stage 1 — 2-round distinguisher',
          f'- Trials: {cfg["trials"]}/{cfg["trials"]} PASS, with 2 disjoint full 256-text multisets each',
          '- All 16 internal X2 byte XOR sums were zero for each multiset',
          '- Key material: **genuine master-key expansions**, no weak-key restriction',
          '']
    r += ['## Stage 2 — 3-round key filtering',
          f'- Correct 64-bit column keys retained: {2*cfg["trials"]}/{2*cfg["trials"]}',
          '- The complete genuine K3 belongs to the Cartesian product of the tested per-column survivors',
          '- K2 obtained from K3 by the reference odd/even key relation',
          f'- Chosen plaintexts: 2 x 256 = 512 per trial',
          '- Modular terminal subtraction includes bytewise borrow propagation',
          '- Estimated exhaustive work in paper: 2^74 **column partial decryptions**, not full encryptions',
          '', '### Wrong candidate testing',
          '| Column | Family | Evaluations | Survive first | Survive both |',
          '|---|---|---:|---:|---:|']
    for e in rows:
        r.append(f'| {e["column"]} | {e["family"]} | {e["evaluations"]} | {e["survivors_after_first"]} | {e["survivors_after_both"]} |')
    r += ['', 'Wrong-candidate tests are **not** an exhaustive search; statistical independence and unique master-key recovery are not established.',
          'Counts across families can overlap. Per-trial counts and true subkeys are saved under trials/.',
          'The first-trial vectors are saved in reproducible_test_vectors.json.', '']
    (outdir/'REPORT.md').write_text('\n'.join(r),encoding='utf-8')
    return report


def main():
    parser=argparse.ArgumentParser(description='Kalyna-128/128: 1000 genuine-master 2R distinguisher + 3R filtering trials')
    parser.add_argument('--trials',type=int,default=1000)
    parser.add_argument('--random-wrong',type=int,default=64,
                       help='Uniform random incorrect 64-bit columns per column per trial')
    parser.add_argument('--jobs',type=int,default=4)
    parser.add_argument('--chunk-size',type=int,default=48)
    parser.add_argument('--seed',type=int,default=20261117)
    parser.add_argument('--no-full-msb',action='store_true',help='Disable the all-255 wrong MSB-byte slice')
    parser.add_argument('--out',type=Path,default=Path('KALYNA128_128_R3_COMBINED_RESULTS'))
    parser.add_argument('--resume',action='store_true')
    parser.add_argument('--self-test',action='store_true')
    parser.add_argument('--progress-every',type=int,default=25)
    args=parser.parse_args()
    if min(args.trials,args.jobs,args.chunk_size,args.progress_every)<1 or args.random_wrong<0 or args.seed<0:
        parser.error('trials/jobs/chunk-size/progress-every must be positive; random-wrong and seed nonnegative')
    print('KALYNA-128/128: 2R integral + 3R key-candidate filtering',flush=True)
    print('[reference vectors / arithmetic / partial inversion]',flush=True)
    official=selftest()
    print('  '+official['status']+' (official KATs, round inverse, carry/borrow, wrong-key partial inverse)',flush=True)
    if args.self_test:
        print(json.dumps(official,indent=2))
        return 0
    cfg={'trials':args.trials,'random_wrong':args.random_wrong,'chunk_size':args.chunk_size,
         'seed':args.seed,'full_msb':not args.no_full_msb}
    current=Path(__file__)
    config={'parameters':cfg,'source_file':current.name,
            'source_sha256':hashlib.sha256(current.read_bytes()).hexdigest(),
            'numpy':np.__version__,'version':VERSION}
    outdir=args.out
    cfgfile=outdir/'config.json'
    if args.resume:
        require(cfgfile.exists(),'cannot resume, config.json missing')
        require(json.loads(cfgfile.read_text())==config,
                'resume refused: configuration or script hash does not match')
    else:
        require(not outdir.exists() or not any(outdir.iterdir()),
                'output directory is not empty, use --resume or a new --out')
    (outdir/'trials').mkdir(parents=True,exist_ok=True)
    atomic_json(cfgfile,config)
    atomic_json(outdir/'selftest.json',official)
    atomic_json(outdir/'environment.json',{'python':sys.version,'platform':platform.platform(),
                                          'numpy':np.__version__})
    completed=[];pending=[]
    for i in range(args.trials):
        f=outdir/'trials'/f'{i:05d}.json'
        if f.exists():
            data=json.loads(f.read_text())
            require(data.get('trial')==i and data.get('status')=='PASS','invalid checkpoint '+str(f))
            completed.append(i)
        else:
            pending.append(i)
    print(f'[config] trials={args.trials} completed={len(completed)} pending={len(pending)} '
          f'jobs={args.jobs} random_wrong={args.random_wrong} 255_MSB={not args.no_full_msb}',flush=True)
    print('[STAGE 1] 2-round 256-plaintext distinguisher; 16 balanced internal bytes',flush=True)
    print('[STAGE 2] 3-round final modular addition; two multisets; Algorithm 1 + odd-key Algorithm 2',flush=True)
    start=time.monotonic()
    lasttime=start
    all_pass=len(completed)
    def save(d):
        nonlocal all_pass,lasttime
        atomic_json(outdir/'trials'/f'{d["trial"]:05d}.json',d)
        all_pass+=1
        now=time.monotonic()
        if d['trial']==0 or all_pass%args.progress_every==0 or all_pass==args.trials or now-lasttime>=25:
            d1=d['distinguisher']['results'];k=d['key_filtering']['columns']
            wrong=sum(e['deduplicated_wrong_testing']['unique_wrong_surviving_both_multisets'] for e in k)
            print(f'[progress {all_pass}/{args.trials} elapsed={now-start:.1f}s] '
                  f'DIST={d1[0]["round2_zero_xor_bytes"]}/16+{d1[1]["round2_zero_xor_bytes"]}/16 '
                  f'KEY=true K3 cols 2/2; tested wrong survivors(col-sum)={wrong}',flush=True)
            lasttime=now
        if d['trial']==0:
            print('  [trial 0 | DISTINGUISHER] '
                  f'X0={d1[0]["round0_post_prewhitening"]}, '
                  f'X1={d1[0]["round1"]}, X2={d1[0]["round2"]}; '
                  '16/16 zero XOR sums',flush=True)
            print('  [trial 0 | KEY RECOVERY] K3='
                  +d['key_filtering']['correct_K3_terminal_128bit_hex'],flush=True)
            print('  [trial 0 | KEY RECOVERY] derived K2='
                  +d['key_filtering']['derived_K2_128bit_hex'],flush=True)
            for i,e in enumerate(k):
                print(f'  [trial 0] column={i} I_j={e["index_set_Ij"]} '
                      f'correct={e["true_terminal_64bit_key_hex"]} '
                      f'wrong_after_two={e["deduplicated_wrong_testing"]["unique_wrong_surviving_both_multisets"]}',flush=True)
    if args.jobs==1:
        for i in pending:
            save(one_trial(i,cfg))
    else:
        with ProcessPoolExecutor(max_workers=args.jobs) as pool:
            futures={pool.submit(one_trial,i,cfg):i for i in pending}
            while futures:
                done,_=wait(futures,timeout=25,return_when=FIRST_COMPLETED)
                for future in done:
                    trial_no=futures.pop(future)
                    try:
                        save(future.result())
                    except Exception:
                        print(f'[FAILED] trial={trial_no}; saved results are resumable',flush=True)
                        raise
                if not done:
                    print(f'[heartbeat elapsed={time.monotonic()-start:.1f}s] '
                          f'completed={all_pass}/{args.trials}',flush=True)
    report=summarize(outdir,cfg)
    print('[COMPLETE] '+str(report['distinguisher']['positive_trials'])+' distinguisher trials PASS; '
           +str(report['key_filtering']['true_terminal_64bit_column_candidates_retained'])
           +' correct terminal key-column tests PASS',flush=True)
    print(f'[files] {outdir}/REPORT.md, summary.json, wrong_key_survivors.csv, '
          'reproducible_test_vectors.json, trials/',flush=True)
    print('[scope] sampled wrong columns only; no complete master-key recovery',flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
