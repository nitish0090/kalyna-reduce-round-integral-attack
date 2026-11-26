#!/usr/bin/env python3
"""Kalyna-256/256: 3-round key-independent integral + 4-round key-column filtering.

Standalone, independently checked against the designers' official
Kalyna-256/256 full-round encryption vector. Research validation only.

State: 4 x 8 bytes, column-major, little-endian 64-bit words.
Round convention: K[0] unrestricted modular pre-whitening, XOR internal
round keys, K[4] terminal modular addition in the 4-round reduced target.
The distinguisher checks X3 after XOR with K[3], before the fourth round. Two active input
bytes at positions 6 and 7 enumerate the full product F_256^2.

The full 2^64 column keyspace is NEVER enumerated. All wrong-key tests
are explicitly sampled/structured; master-key recovery is NOT claimed.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
import platform
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
import numpy as np

VERSION = '2.0-k256256-r4-unrestricted-6-7'
REFERENCE = 'https://github.com/Roman-Oliynykov/Kalyna-reference'
REFERENCE_COMMIT = '22eafbcaf6635dc5e1f8a734b1f7c5ab84b5a5ea'

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
BLOCK_BYTES = 32
COLS = 4
ROWS = 8
ROUNDS = 14
SHIFT = np.array([r//2 for r in range(8)], dtype=np.intp)
# Forward SR maps each output byte to the original (source) byte.
SR = np.array([8*((c-int(SHIFT[r]))%4)+r
               for c in range(COLS) for r in range(ROWS)], dtype=np.intp)
IS = np.argsort(SR)
I_SETS = [tuple(int(SR[8*j+r]) for r in range(8)) for j in range(4)]


def gf(a,b,poly=0x11d):
    z=0
    for _ in range(8):
        if b&1: z^=a
        a<<=1
        if a&0x100: a^=poly
        b>>=1
    return z

GF = np.array([[gf(a,b) for b in range(256)] for a in range(256)],dtype=np.uint8)


def a8(x):
    return np.asarray(x,dtype=np.uint8)


def mix(x,inv=False):
    x=a8(x)
    if x.shape[-1]%8: raise ValueError('Expected whole 64-bit columns')
    reshaped=x.reshape(x.shape[:-1]+(-1,8))
    out=np.zeros_like(reshaped)
    mat=IMDS if inv else MDS
    for row in range(8):
        for v in range(8):
            out[...,row]^=GF[mat[row,v],reshaped[...,v]]
    return out.reshape(x.shape)


def F(x):
    x=a8(x)
    return mix(SBOX[np.arange(x.shape[-1])%4,x][...,SR])


def Finv(x):
    x=a8(x)
    v=mix(x,True)[...,IS]
    return INV_SBOX[np.arange(v.shape[-1])%4,v]


def add64(x,key,subtract=False):
    x,key=np.broadcast_arrays(a8(x),a8(key))
    if x.shape[-1]%8: raise ValueError('Expected whole 64-bit columns')
    xx=x.reshape(x.shape[:-1]+(-1,8)).astype(np.int16)
    kk=key.reshape(key.shape[:-1]+(-1,8)).astype(np.int16)
    yy=np.empty_like(xx,dtype=np.uint8)
    carry=np.zeros(xx.shape[:-1],dtype=np.int16)
    for r in range(8):
        v=xx[...,r]-kk[...,r]-carry if subtract else xx[...,r]+kk[...,r]+carry
        yy[...,r]=(v&255).astype(np.uint8)
        carry=(v<0).astype(np.int16) if subtract else (v>>8)
    return yy.reshape(x.shape)


def sub64(x,key):
    return add64(x,key,True)


def odd_from_even(k):
    # Official RotateLeft: 2*nb+3 = 11 BYTES for 256-bit state.
    return np.roll(a8(k),-11,axis=-1)


def even_from_odd(k):
    return np.roll(a8(k),11,axis=-1)


def expand_key(master):
    """Exact 256/256 Kalyna schedule, 15 x 256-bit subkeys K[0]..K[14]."""
    key=a8(master)
    if key.shape!=(32,): raise ValueError('256-bit key required')
    s=np.zeros(32,dtype=np.uint8)
    s[0]=4+4+1
    kt=F(add64(F(F(add64(s,key))^key),key))
    keys=np.empty((15,32),dtype=np.uint8)
    tmv=np.tile(np.array([1,0,1,0,1,0,1,0],dtype=np.uint8),4)
    data=key.copy()
    for r in range(0,15,2):
        tmp=add64(kt,tmv)
        keys[r]=add64(F(F(add64(data,tmp))^tmp),tmp)
        if r<14:
            tmv=add64(tmv,tmv)
            data=np.roll(data,-8)  # official Rotate: one 64-bit word
    for r in range(1,14,2):
        keys[r]=odd_from_even(keys[r-1])
    return keys


def encrypt_full(p,keys):
    if keys.shape!=(15,32): raise ValueError('Full key schedule required')
    x=add64(p,keys[0])
    for r in range(1,14): x=F(x)^keys[r]
    return add64(F(x),keys[14])


def decrypt_full(c,keys):
    x=Finv(sub64(c,keys[14]))
    for r in range(13,0,-1): x=Finv(x^keys[r])
    return sub64(x,keys[0])


def xorsum(v):
    return np.bitwise_xor.reduce(a8(v),axis=-2)


def verify_primitives():
    # Official authors' 256/256 reference main.c (little-endian byte layout).
    key=np.arange(32,dtype=np.uint8)
    pt=np.arange(32,64,dtype=np.uint8)
    expected='f66e3d570ec92135aedae323dcbd2a8ca03963ec206a0d5a88385c24617fd92c'
    keys=expand_key(key)
    actual=encrypt_full(pt,keys).tobytes().hex()
    if actual!=expected:
        raise AssertionError(f'Official 256/256 vector FAILED: {actual} != {expected}')
    if not np.array_equal(decrypt_full(np.frombuffer(bytes.fromhex(expected),dtype=np.uint8),keys),pt):
        raise AssertionError('Official 256/256 decrypt check failed')
    rng=np.random.default_rng(7319)
    for _ in range(4):
        v=rng.integers(0,256,(7,32),dtype=np.uint8)
        k=rng.integers(0,256,32,dtype=np.uint8)
        if not np.array_equal(Finv(F(v)),v): raise AssertionError('F inverse failed')
        if not np.array_equal(sub64(add64(v,k),k),v): raise AssertionError('Modular subtraction failed')
        if not np.array_equal(even_from_odd(odd_from_even(k)),k): raise AssertionError('Key rotation failed')
    minors = [int(GF[MDS[j,6],MDS[ell,7]]) ^ int(GF[MDS[j,7],MDS[ell,6]])
              for j in range(8) for ell in range(j+1,8)]
    if len(minors)!=28 or not all(minors):
        raise AssertionError('MDS columns 6,7 minor check failed')
    assert set(I_SETS[0])=={0,1,14,15,20,21,26,27}
    return dict(official_reference='PASS',ciphertext=expected,key=key.tobytes().hex(),
                plaintext=pt.tobytes().hex(),roundtrip='PASS',state_inversion='PASS',
                terminal_64bit_subtraction='PASS',round_key_rotation='PASS',
                mds_columns_6_7_nonsingular_minors=28)


# ========================================================================
#  Section 4.2 two-active-byte key-independent distinguisher -> 4R Algorithm 1
# ========================================================================
ACTIVE = (6, 7)
N = 1 << 16
DATA = 2 * N
N_COLS = 4


def plaintext_structures(rng):
    """Two disjoint full F_256 x F_256 products; unrestricted pre-whitening.

    Inputs are P(x,y)=a xor x e6 xor y e7. The offset byte 4 is
    constant in each structure and differs between structures.
    """
    a = rng.integers(0, 256, 32, dtype=np.uint8)
    a[6] = 0
    a[7] = 0
    a[4] = 0
    p = np.tile(a, (N, 1))
    p[:, 6] = np.repeat(np.arange(256, dtype=np.uint8), 256)
    p[:, 7] = np.tile(np.arange(256, dtype=np.uint8), 256)
    p2 = p.copy()
    offset = int(rng.integers(1, 256))
    p2[:, 4] = np.uint8(offset)
    return (p, p2), offset


def encrypt4(p, k):
    x0 = add64(p, k[0])
    x1 = F(x0) ^ k[1]
    x2 = F(x1) ^ k[2]
    x3 = F(x2) ^ k[3]
    c = add64(F(x3), k[4])
    return (x0, x1, x2, x3), c


def check_full_product_two_bytes(state, positions=ACTIVE):
    """Check that (byte[6],byte[7]) enumerates F_256^2 exactly once."""
    if state.shape[0] != N:
        return False
    u = state[:, positions[0]].astype(np.uint16)
    v = state[:, positions[1]].astype(np.uint16)
    pairs = u * 256 + v
    return bool(np.all(np.bincount(pairs,minlength=N)==1))


def check_distinguishers(ps, k):
    """Check strict input/full product, PW, 1R, 2R and 3R on BOTH multisets."""
    if not np.array_equal(k[1],odd_from_even(k[0])): raise AssertionError('K1 rotation')
    if not np.array_equal(k[3],odd_from_even(k[2])): raise AssertionError('K3 rotation')
    if int(ps[0][0,4])==int(ps[1][0,4]):
        raise AssertionError('Two plaintext multisets are not disjoint')
    state_sets=[]
    counts=[]
    for p in ps:
        if p.shape!=(N,32) or not check_full_product_two_bytes(p):
            raise AssertionError('Invalid two-byte full product')
        if np.any(p[:,[i for i in range(32) if i not in ACTIVE]] !=
                  p[0,[i for i in range(32) if i not in ACTIVE]]):
            raise AssertionError('Incorrect constants in plaintext multiset')
        states, ct = encrypt4(p,k)
        x0,x1,x2,x3=states
        if not check_full_product_two_bytes(x0):
            raise AssertionError('Full product destroyed by pre-whitening')
        if np.any(x0[:,[i for i in range(32) if i not in ACTIVE]] !=
                  x0[0,[i for i in range(32) if i not in ACTIVE]]):
            raise AssertionError('Pre-whitening changed a constant input byte')
        # Verify all 28 pairs of output bytes in the fourth column.
        for j in range(24,32):
            for ell in range(j+1,32):
                if not check_full_product_two_bytes(x1, positions=(j,ell)):
                    raise AssertionError(('First round pairwise joint uniformity failed', j, ell))
        if np.any(x1[:, :24] != x1[0, :24]):
            raise AssertionError('Unexpected first-round activity outside column 3')
        # Every second-round byte must take each value exactly 256 times.
        second_uniform = all(np.all(np.bincount(x2[:,i],minlength=256)==256)
                             for i in range(32))
        if not second_uniform: raise AssertionError('2R All property failed')
        s = xorsum(x3)
        if np.any(s): raise AssertionError(('3R integral failed',s.tolist()))
        back = Finv(sub64(ct, k[4]))
        if not np.array_equal(back,x3):
            raise AssertionError('True 4R pointwise partial inverse FAILED')
        state_sets.append((states,ct))
        counts.append(int(np.count_nonzero(s==0)))
    return state_sets,counts


def col_balance_for_guesses(cts,j,guess_cols,first_only=False,batch_size=8):
    """Algorithm 1 on complete columns (full borrow & inverse MC).

    Inverse ShiftRows is accounted for by I_j. For each output MC row t,
    the inverse-S-box value is assigned to physical index SR[8*j+t].
    Balancing all eight values makes this permutation irrelevant to pass/fail.
    """
    if not guess_cols:return [],0,0
    col0=cts[0][:,j*8:j*8+8]
    col1=cts[1][:,j*8:j*8+8]
    survivors=[];pass_first=0;tested=0
    for start in range(0,len(guess_cols),batch_size):
        guesses=np.stack(guess_cols[start:start+batch_size]).astype(np.uint8)
        # Broadcast [B,1,8] against [1,N,8] to get [B,N,8].
        v=mix(sub64(col0[None,:,:],guesses[:,None,:]),inv=True)
        pre=INV_SBOX[np.arange(8)%4,v]
        sums=np.bitwise_xor.reduce(pre,axis=1)
        passed=np.all(sums==0,axis=1)
        n=int(np.count_nonzero(passed))
        pass_first+=n;tested+=len(guesses)
        if not first_only and n:
            passed_indices=np.flatnonzero(passed)
            selected=guesses[passed_indices]
            v1=mix(sub64(col1[None,:,:],selected[:,None,:]),inv=True)
            pre1=INV_SBOX[np.arange(8)%4,v1]
            sums1=np.bitwise_xor.reduce(pre1,axis=1)
            both=np.all(sums1==0,axis=1)
            survivors.extend(selected[both].tolist())
    return survivors,pass_first,tested


def candidate_columns(keycol,rng,trial,j,random_wrong,single_bit_wrong,msb_differences,full_msb):
    """Sampled + adversarial wrong subkey columns; never enumerates 2^64."""
    k=a8(keycol)
    observed=set()
    def add(q):
        q=a8(q).tobytes()
        if q!=k.tobytes(): observed.add(q)
    for _ in range(random_wrong):
        add(rng.integers(0,256,8,dtype=np.uint8))
    for n in range(min(64,single_bit_wrong)):
        q=k.copy(); bit=(trial*29+j*13+n*17)%64
        q[bit//8]^=np.uint8(1<<(bit%8));add(q)
    if full_msb:
        for difference in range(1,256):
            q=k.copy();q[7]^=np.uint8(difference);add(q)
    else:
        for n in range(min(255,msb_differences)):
            difference=1+(trial*37+j*43+n*17)%255
            q=k.copy();q[7]^=np.uint8(difference);add(q)
    # The 2^63 high bit is especially important: modular addition can
    # coincide with XOR for this difference.
    trueval=int.from_bytes(k.tobytes(),'little')
    for d in (1,-1,1<<56,1<<63):
        add(np.frombuffer(((trueval+d)%(1<<64)).to_bytes(8,'little'),dtype=np.uint8))
    return [np.frombuffer(x,dtype=np.uint8).copy() for x in sorted(observed)]


def run_trial(trial,seed,random_wrong,single_bit_wrong,msb_differences,full_msb_trials):
    rng=np.random.default_rng(np.random.SeedSequence([seed,trial,2562564]))
    master=rng.integers(0,256,32,dtype=np.uint8)
    k=expand_key(master)
    ps,offset=plaintext_structures(rng)
    both,counts=check_distinguishers(ps,k)
    cts=[ct for _,ct in both]
    tested=0;wrong_first=0;wrong_both=0;correct_retained=0;wrong_survivors=[]
    exhaustive_msb=trial<full_msb_trials
    for j in range(4):
        keycol=k[4,8*j:8*(j+1)]
        true,first,num=col_balance_for_guesses(cts,j,[keycol])
        if first!=1 or len(true)!=1 or not np.array_equal(true[0],keycol):
            raise AssertionError(('Correct K4 column rejected',trial,j))
        correct_retained+=1
        guesses=candidate_columns(keycol,rng,trial,j,random_wrong,single_bit_wrong,msb_differences,exhaustive_msb)
        surviving,passed0,ntested=col_balance_for_guesses(cts,j,guesses)
        tested+=ntested;wrong_first+=passed0;wrong_both+=len(surviving)
        for v in surviving:
            wrong_survivors.append(dict(trial=trial,column=j,guess=bytes(v).hex(),true_key=keycol.tobytes().hex()))
    record=dict(trial=trial,seed=seed,model='genuine_Kalyna256_256_master_key_expansion',
                key_restriction='none',
                actual_master_key=master.tobytes().hex(),subkey_fraction='1',
                plaintexts_per_multiset=N,chosen_plaintexts=DATA,
                distinguisher_passed=True,balanced_bytes_per_multiset=counts,
                correct_K4_columns_retained=correct_retained,
                wrong_column_candidates_tested=tested,
                wrong_pass_first_multiset=wrong_first,
                wrong_survive_both_multisets=wrong_both,
                second_structure_offset_byte4=offset,
                exhaustive_msb_differences=exhaustive_msb)
    vectors=None
    if trial==0:
        vectors=dict(official_full_cipher_KAT=verify_primitives(),
                     model=record['model'],restriction=record['key_restriction'],
                     master_key=master.tobytes().hex(),
                     round_keys=[z.tobytes().hex() for z in k],
                     index_sets=I_SETS,active_positions=list(ACTIVE),offset_byte4=offset,
                     multisets=[])
        for (p,(states,ct)) in zip(ps,both):
            x0,x1,x2,x3=states
            vectors['multisets'].append(dict(
                plaintext_at_xy_0_0=p[0].tobytes().hex(),
                plaintext_at_xy_0_1=p[1].tobytes().hex(),
                plaintext_at_xy_1_0=p[256].tobytes().hex(),
                plaintext_at_xy_255_255=p[-1].tobytes().hex(),
                ciphertext_xy_0_0=ct[0].tobytes().hex(),
                x0_xy_0_0=x0[0].tobytes().hex(),
                x1_xy_0_0=x1[0].tobytes().hex(),
                x2_xy_0_0=x2[0].tobytes().hex(),
                x3_xy_0_0=x3[0].tobytes().hex(),
                round3_balanced_xor=xorsum(x3).tobytes().hex(),
                ciphertext_xor=xorsum(ct).tobytes().hex()))
    return record,wrong_survivors,vectors


def main():
    p=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument('--trials',type=int,default=1000)
    p.add_argument('--seed',type=int,default=20261117)
    p.add_argument('--jobs',type=int,default=4)
    p.add_argument('--random-wrong',type=int,default=2)
    p.add_argument('--single-bit-wrong',type=int,default=2)
    p.add_argument('--msb-differences',type=int,default=2)
    p.add_argument('--full-msb-trials',type=int,default=0)
    p.add_argument('--progress-every',type=int,default=25)
    p.add_argument('--out',default='KALYNA256_256_R4_UNRESTRICTED_RESULTS')
    p.add_argument('--resume',action='store_true')
    args=p.parse_args()
    if args.trials<1 or args.jobs<1 or args.full_msb_trials<0 or args.progress_every<1 or min(args.random_wrong,args.single_bit_wrong,args.msb_differences)<0:
        p.error('Invalid count or jobs value')
    out=Path(args.out);out.mkdir(parents=True,exist_ok=True)
    options=dict(trials=args.trials,seed=args.seed,random_wrong=args.random_wrong,
                 single_bit_wrong=args.single_bit_wrong,msb_differences=args.msb_differences,
                 full_msb_trials=args.full_msb_trials)
    source_hash=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    sf=out/'settings.json'
    if args.resume and sf.exists():
        saved=json.loads(sf.read_text())
        if saved['options']!=options or saved['source_sha256']!=source_hash:
            raise ValueError('Cannot resume changed settings or source')
    else:
        if (out/'trials.jsonl').exists(): raise FileExistsError('Output exists; use --resume or new --out')
        sf.write_text(json.dumps(dict(options=options,source_sha256=source_hash,
            reference=REFERENCE,reference_commit=REFERENCE_COMMIT,
            numpy=np.__version__,python=sys.version,platform=platform.platform()),indent=2))
    kats=verify_primitives()
    (out/'official_known_answer.json').write_text(json.dumps(kats,indent=2))
    completed={}
    if args.resume and (out/'trials.jsonl').exists():
        for line in (out/'trials.jsonl').read_text().splitlines():
            if line.strip():
                record=json.loads(line);completed[record['trial']]=record
    pending=[i for i in range(args.trials) if i not in completed]
    tstart=time.perf_counter()
    print('Kalyna-256/256: 3R key-independent integral -> 4R key candidate filtering',flush=True)
    print('Official 256/256 KAT: PASS; 4 columns; genuine expanded master keys',flush=True)
    print('Key restrictions: NONE; admissible subkey fraction 1',flush=True)
    print('Input: a xor x*e6 xor y*e7, full x,y in F_256, 2 x 65536 texts',flush=True)
    print('Algorithms: 1 only (even terminal round R=4); 64-bit modular subtraction',flush=True)
    print('Inverse-SR index sets:',I_SETS,flush=True)
    print(f'Resuming: {len(completed)} completed, {len(pending)} remaining',flush=True)
    def save(result):
        record,survivors,vectors=result
        if record['trial'] in completed:return
        completed[record['trial']]=record
        with (out/'trials.jsonl').open('a') as f: f.write(json.dumps(record,sort_keys=True)+'\n')
        if survivors:
            with (out/'wrong_key_survivors.jsonl').open('a') as f:
                for v in survivors:f.write(json.dumps(v,sort_keys=True)+'\n')
        if vectors is not None:
            (out/'reproducible_test_vectors.json').write_text(json.dumps(vectors,indent=2))
        count=len(completed)
        if count%args.progress_every==0 or count==args.trials:
            elapsed=time.perf_counter()-tstart
            correct=sum(a['correct_K4_columns_retained'] for a in completed.values())
            wrong=sum(a['wrong_survive_both_multisets'] for a in completed.values())
            print(f'Progress {count}/{args.trials}; correct {correct}/{4*count}; wrong survivors {wrong}; '
                  f'elapsed {elapsed:.1f}s',flush=True)
    if args.jobs==1:
        for trial in pending:
            save(run_trial(trial,args.seed,args.random_wrong,args.single_bit_wrong,
                           args.msb_differences,args.full_msb_trials))
    else:
        with ProcessPoolExecutor(max_workers=args.jobs) as exe:
            futures={exe.submit(run_trial,trial,args.seed,args.random_wrong,args.single_bit_wrong,
                                args.msb_differences,args.full_msb_trials):trial
                     for trial in pending}
            for future in as_completed(futures): save(future.result())
    ordered=[completed[t] for t in range(args.trials)]
    assert all(x['distinguisher_passed'] and x['correct_K4_columns_retained']==4 for x in ordered)
    columns=['trial','seed','model','actual_master_key','subkey_fraction','chosen_plaintexts',
        'distinguisher_passed','correct_K4_columns_retained','wrong_column_candidates_tested',
        'wrong_pass_first_multiset','wrong_survive_both_multisets','second_structure_offset_byte4',
        'exhaustive_msb_differences']
    with (out/'trial_summary.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=columns);writer.writeheader()
        for rec in ordered:writer.writerow({x:rec.get(x) for x in columns})
    total=dict(trials=args.trials,distinguishers_passed=sum(x['distinguisher_passed'] for x in ordered),
        valid_multisets=2*args.trials,plaintexts_per_multiset=N,chosen_plaintexts=DATA,
        active_positions=list(ACTIVE),key_restriction='none',
        balanced_bytes_per_multiset=32,subkey_fraction='1',admissible_subkey_count='2^256',
        correct_K4_columns_retained=sum(x['correct_K4_columns_retained'] for x in ordered),
        correct_K4_columns_expected=4*args.trials,
        wrong_column_candidates_tested=sum(x['wrong_column_candidates_tested'] for x in ordered),
        wrong_pass_first_multiset=sum(x['wrong_pass_first_multiset'] for x in ordered),
        wrong_survive_both_multisets=sum(x['wrong_survive_both_multisets'] for x in ordered),
        nominal_exhaustive_work='2^83 64-bit column partial-decryption operations',
        source_sha256=source_hash,master_key_schedule_compatibility='GENUINE EXPANDED KEYS IN ALL TRIALS',
        exhaustive_2power64_column_search=False,full_master_key_recovered=False,
        wall_seconds_this_session=round(time.perf_counter()-tstart,3))
    (out/'summary.json').write_text(json.dumps(total,indent=2))
    report="""# Kalyna-256/256 — 3-round key-independent distinguisher -> 4-round candidate filtering

"""
    report+='\n'.join(f'- **{k}**: {v}' for k,v in total.items())
    report+="""

## Referee-focused scope
The updated manuscript Table 2 row is (Kalyna-256/256, R=4, 2^17 chosen
plaintexts, 2^83 nominal 64-bit column partial decryptions, subkey
fraction 1, Algorithm 1). The input structure is the full F_256^2
product {a xor x e6 xor y e7}; each multiset contains 65536 texts.
The two active bytes form the upper 16-bit word of the first column.
The lower six constant bytes produce a fixed carry into that word;
modular addition translates the full word modulo 2^16, preserving the
complete product for every fixed pre-whitening subkey. All 28 pairs of
first-round output bytes in column 3 are tested for joint uniformity.
No key bytes are fixed, no master keys are rejected or modified.
All trial subkeys come from the genuine Kalyna-256/256 key schedule.
The integral is verified at X3, after the third XOR internal-round
key and before terminal modular addition. 4R ciphertext C=F(X3) boxplus K4.
The filter guesses each K4 64-bit column, subtracts modulo 2^64
with full borrow, performs inverse MixColumns and inverse S-boxes, and
checks all eight relevant bytewise XOR sums on both structures. The
per-column inverse ShiftRows mapping uses exactly I_j; it is not
performed on an isolated column. All candidate survivors are recorded.
The terminal index R=4 is EVEN: Algorithm 2 does not derive K3 from K4.
The nominal 2^83 work estimate is NOT full-encryption work, and is
not performed by this program. No uniqueness or master-key recovery is
claimed. Incorrect subkeys are a finite structured/sampled experiment.
No weak-key condition is imposed; the construction applies to every master key.
The experiment tests correct-candidate retention, not exhaustive key recovery.
"""
    (out/'REPORT.md').write_text(report)
    print('COMPLETE',json.dumps(total,indent=2),flush=True)
    return 0

if __name__=='__main__':
    raise SystemExit(main())
