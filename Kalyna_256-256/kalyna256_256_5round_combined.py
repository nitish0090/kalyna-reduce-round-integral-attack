#!/usr/bin/env python3
"""Kalyna-256/256: 4-round weak-prewhitening integral + 5-round key-column filtering.

Standalone, independently checked against the designers' official
Kalyna-256/256 full-round encryption vector. Research validation only.

State: 4 x 8 bytes, column-major, little-endian 64-bit words.
Round convention: K[0] modular pre-whitening (8 restricted zero bytes),
XOR internal keys K[1]..K[4], and terminal addition K[5] mod 2^64.
The 4-round distinguisher checks X4 BEFORE the fifth-round addition.
Plaintexts are F^{-1}(F(0) xor x*e6 xor y*e7), full F_256^2.

The full 2^64 column keyspace is NEVER enumerated. All wrong-key tests
are explicitly sampled/structured; master-key recovery is NOT claimed.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
import os
import platform
import sys
import time
from functools import lru_cache
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
import numpy as np

VERSION = '2.0-k256256-r5-weak4-active6-7'
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


def states_for(p,keys):
    x0=add64(p,keys[0])
    x1=F(x0)^keys[1]
    x2=F(x1)^keys[2]
    return x0,x1,x2


def encrypt3(p,keys):
    _,_,x2=states_for(p,keys)
    return add64(F(x2),keys[3])


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
    assert set(I_SETS[0])=={0,1,14,15,20,21,26,27}
    for matrix in (MDS, IMDS):
        for r in range(8):
            for t in range(r+1,8):
                if not (GF[matrix[r,6],matrix[t,7]] ^ GF[matrix[r,7],matrix[t,6]]):
                    raise AssertionError('Noninvertible 2x2 minor for columns 6,7')
    return dict(official_reference='PASS',ciphertext=expected,key=key.tobytes().hex(),
                plaintext=pt.tobytes().hex(),roundtrip='PASS',state_inversion='PASS',
                terminal_64bit_subtraction='PASS',round_key_rotation='PASS',
                MDS_and_inverse_28_minors_columns_6_7='PASS')


# ============================================================================
# Section 4.3 backward-extended two-active-byte 4R integral -> 5R (Algorithm 2)
# ============================================================================
# Both active bytes belong to column 0; their inverse supports coincide.
I_WEAK = (0, 1, 14, 15, 20, 21, 26, 27)
ACTIVE = (6, 7)
N = 1 << 16
DATA = 2*N
OFFSET_BYTE = 2       # In column 0, strictly above variable rows 0 and 1
N_COLS = 4


@lru_cache(maxsize=1)
def p4_base():
    """The EXACT F^{-1}(F(0) xor x*e6 xor y*e7) full 65536-set.

    The whole array is cached per worker process. No plaintext construction
    depends on unknown encryption subkeys.
    """
    zero=np.zeros(32,dtype=np.uint8)
    u=np.broadcast_to(F(zero),(N,32)).copy()
    u[:,ACTIVE[0]] ^= np.repeat(np.arange(256,dtype=np.uint8),256)
    u[:,ACTIVE[1]] ^= np.tile(np.arange(256,dtype=np.uint8),256)
    p=Finv(u)
    if not np.array_equal(F(p),u): raise AssertionError('Exact P4 inverse failed')
    if np.any(p[:,[i for i in range(32) if i not in I_WEAK]]):
        raise AssertionError('Unexpected nonzero plaintext bytes outside I_WEAK')
    # Independently evaluate Appendix B.3's exact byte formula.
    x = np.repeat(np.arange(256, dtype=np.uint8), 256)
    y = np.tile(np.arange(256, dtype=np.uint8), 256)
    expected = np.zeros_like(p)
    for r in range(8):
        c = (-int(SHIFT[r])) % 4
        b = 8*c+r
        expected[:,b] = INV_SBOX[r%4, SBOX[r%4,0] ^ GF[IMDS[r,6],x] ^ GF[IMDS[r,7],y]]
        if not np.all(np.bincount(p[:,b], minlength=256)==256):
            raise AssertionError('Inverse-defined All property failed')
    if not np.array_equal(p,expected) or np.any(p[0]):
        raise AssertionError('Appendix B.3 exact byte formula failed')
    if tuple(np.flatnonzero(np.any(p!=p[0],axis=0))) != I_WEAK:
        raise AssertionError('Inverse support mismatch')
    if not np.all(p[:,OFFSET_BYTE]==0):
        raise AssertionError('Incorrect safe offset index')
    p.flags.writeable=False
    return p


def plaintext_structures(rng):
    """Two disjoint, FULL 2^16 structures with safe upper-column offset.

    The second one is P4(x,y) xor a*e2, a != 0, in a byte strictly
    ABOVE variable support within its column. Under the weak Kpw condition,
    any resulting carries remain independent of x,y.
    """
    p0=p4_base()
    offset=int(rng.integers(1,256))
    p1=p0.copy()
    p1[:,OFFSET_BYTE] ^= np.uint8(offset)
    return (p0,p1),offset


def synthetic_restricted_keys(rng):
    """Valid 256-bit reduced-state round model with weak Kpw and rotations.

    K[1]=Rot(K[0]), K[3]=Rot(K[2]), K[5]=Rot(K[4]).
    Synthetic keys are NOT claimed to arise from a genuine master-key schedule.
    """
    k=rng.integers(0,256,(6,32),dtype=np.uint8)
    k[0,list(I_WEAK)]=0
    for r in (1,3,5): k[r]=odd_from_even(k[r-1])
    return k


def encrypt5(p,k):
    x0=add64(p,k[0])
    x1=F(x0)^k[1]
    x2=F(x1)^k[2]
    x3=F(x2)^k[3]
    x4=F(x3)^k[4]
    ciphertext=add64(F(x4),k[5])
    return (x0,x1,x2,x3,x4),ciphertext


def check_complete_product(v,positions=ACTIVE):
    u=v[:,positions[0]].astype(np.uint16)
    w=v[:,positions[1]].astype(np.uint16)
    return bool(np.all(np.bincount(u.astype(np.int32)*256+w.astype(np.int32),minlength=N)==1))


def full_xor(v):
    return np.bitwise_xor.reduce(v,axis=0)


def check_distinguishers(ps,k,offset):
    if not np.all(k[0,list(I_WEAK)]==0): raise AssertionError('Missing zero Kpw restrictions')
    for r in (1,3,5):
        if not np.array_equal(k[r],odd_from_even(k[r-1])):
            raise AssertionError(f'Invalid odd/even rotation K{r}')
    if not np.array_equal(ps[1][:,OFFSET_BYTE],np.full(N,offset,dtype=np.uint8)):
        raise AssertionError('Second multiset offset not constant')
    if not np.all(ps[0][:,OFFSET_BYTE]==0): raise AssertionError('Bad first offset')
    if offset == 0 or not np.array_equal(np.delete(ps[0],OFFSET_BYTE,axis=1), np.delete(ps[1],OFFSET_BYTE,axis=1)):
        raise AssertionError('Invalid disjoint translated multiset')
    results=[]
    for i,p in enumerate(ps):
        if p.shape!=(N,32): raise AssertionError('Must use all 2^16 plaintexts')
        # This exact set identity (including disjoint translation) is stronger
        # than a row-wise A/C/B/U propagation diagram.
        preimage=F(p)
        src=preimage.copy()
        src[:,list(ACTIVE)]=0
        if not np.all(src==src[0]):
            raise AssertionError('Inverse-defined multiset lost exact 2-byte structure')
        if not check_complete_product(preimage):
            raise AssertionError('Exact input pair is not a full product')
        states,ct=encrypt5(p,k)
        x0,x1,x2,x3,x4=states
        # Carries into variable bytes must not depend on x,y, so the
        # pre-whitening increment is a fixed XOR vector across the structure.
        delta=x0^p
        if not np.all(delta==delta[0]): raise AssertionError('Variable carry from pre-whitening')
        if not np.all(delta[:,list(I_WEAK)]==0):
            raise AssertionError('Weak subkey modified a variable plaintext byte')
        # h = x0 xor base is constant and supported outside I_WEAK.
        h = x0 ^ p4_base()
        if not np.all(h == h[0]) or np.any(h[:,list(I_WEAK)]):
            raise AssertionError('Disjoint-support identity hypotheses failed')
        expected_x1 = np.broadcast_to(F(h[0]) ^ k[1], (N,32)).copy()
        expected_x1[:,6] ^= np.repeat(np.arange(256,dtype=np.uint8),256)
        expected_x1[:,7] ^= np.tile(np.arange(256,dtype=np.uint8),256)
        if not np.array_equal(x1,expected_x1):
            raise AssertionError('Exact first-round identity failed')
        # First round returns exactly a full product on (6,7).
        reduced=x1.copy()
        reduced[:,list(ACTIVE)]=0
        if not np.all(reduced==reduced[0]):
            raise AssertionError('Exact X1 reduction to two active bytes failed')
        if not check_complete_product(x1):
            raise AssertionError('X1 two-variable full product failed')
        # Second round: all 8 bytes in final column are individually All,
        # any two input positions used by subsequent layers have joint rank.
        if not np.all(x2[:,:24]==x2[0,:24]):
            raise AssertionError('Unexpected X2 activity outside column 3')
        for b in range(24,32):
            if not np.all(np.bincount(x2[:,b],minlength=256)==256):
                raise AssertionError('X2 All byte failed')
        for b in range(24,32):
            for d in range(b+1,32):
                if not check_complete_product(x2,(b,d)):
                    raise AssertionError(('X2 pairwise MDS uniformity failed',b,d))
        # Third round individually All across the entire 256-bit state.
        for b in range(32):
            if not np.all(np.bincount(x3[:,b],minlength=256)==256):
                raise AssertionError(('X3 All byte failed',b))
        # Fourth round: every byte balanced PRE-TERMINAL addition.
        sx=full_xor(x4)
        if np.any(sx): raise AssertionError(('X4 Balanced failed',sx.tolist()))
        # Full inverse is checked pointwise, not just through XOR sums.
        if not np.array_equal(Finv(sub64(ct,k[5])),x4):
            raise AssertionError('Correct K5 full inverse did not recover X4')
        results.append((states,ct,preimage))
    return results


def col_filter(cts,j,guesses,batch_size=8):
    """Algorithm 1's column filter; Algorithm 2 applies for odd R=5.

    Each 64-bit guess is subtracted with borrows; inverse MC then inverse
    S-box is applied with correct row-specific Sboxes. The inverse-SR
    permutation only reindexes the 8 tests and is recorded by I_SETS[j].
    """
    if not guesses:return [],0,0
    cols=[c[:,8*j:8*j+8] for c in cts]
    survivors=[];passed_first=0;tested=0
    for start in range(0,len(guesses),batch_size):
        kg=np.stack(guesses[start:start+batch_size]).astype(np.uint8)
        v=mix(sub64(cols[0][None],kg[:,None,:]),inv=True)
        sums=np.bitwise_xor.reduce(INV_SBOX[np.arange(8)%4,v],axis=1)
        good=np.all(sums==0,axis=1)
        tested+=len(kg); passed_first+=int(np.count_nonzero(good))
        if np.any(good):
            accepted=kg[good]
            v2=mix(sub64(cols[1][None],accepted[:,None,:]),inv=True)
            sums2=np.bitwise_xor.reduce(INV_SBOX[np.arange(8)%4,v2],axis=1)
            survivors.extend(accepted[np.all(sums2==0,axis=1)].tolist())
    return survivors,passed_first,tested


def make_wrong_guesses(real,rng,trial,j,random_wrong,single_bit_wrong,msb_differences,full_msb):
    k=a8(real)
    values=set()
    def add(v):
        b=a8(v).tobytes()
        if b!=k.tobytes(): values.add(b)
    for _ in range(random_wrong): add(rng.integers(0,256,8,dtype=np.uint8))
    for n in range(min(64,single_bit_wrong)):
        q=k.copy();bit=(trial*29+j*13+n*17)%64
        q[bit//8]^=np.uint8(1<<(bit%8));add(q)
    count=255 if full_msb else min(255,msb_differences)
    for n in range(count):
        difference=(n+1 if full_msb else 1+(trial*37+j*43+n*17)%255)
        q=k.copy();q[7]^=np.uint8(difference);add(q)
    z=int.from_bytes(k.tobytes(),'little')
    for d in (1,-1,1<<56,1<<63):
        add(np.frombuffer(((z+d)%(1<<64)).to_bytes(8,'little'),dtype=np.uint8))
    return [np.frombuffer(v,dtype=np.uint8).copy() for v in sorted(values)]


def run_trial(trial,seed,random_wrong,single_bit_wrong,msb_differences,full_msb_trials,nonweak_controls):
    rng=np.random.default_rng(np.random.SeedSequence([seed,trial,2562565]))
    k=synthetic_restricted_keys(rng)
    ps,offset=plaintext_structures(rng)
    result=check_distinguishers(ps,k,offset)
    ciphertexts=[row[1] for row in result]
    correct=0;wrong_tested=0;wrong_first=0;wrong_both=0;wrong_survivors=[]
    true_cols=[];sampled_survivors=[]
    exhaustive_msb=trial<full_msb_trials
    for j in range(4):
        kc=k[5,8*j:8*j+8]
        found,first,tested=col_filter(ciphertexts,j,[kc])
        if first!=1 or len(found)!=1 or not np.array_equal(found[0],kc):
            raise AssertionError(('Correct K5 column rejected',trial,j))
        correct+=1;true_cols.append(kc)
        guesses=make_wrong_guesses(kc,rng,trial,j,random_wrong,single_bit_wrong,msb_differences,exhaustive_msb)
        survived,p1,n=col_filter(ciphertexts,j,guesses)
        wrong_tested+=n;wrong_first+=p1;wrong_both+=len(survived)
        sampled_survivors.append(survived)
        for s in survived:wrong_survivors.append(dict(trial=trial,column=j,guess=bytes(s).hex(),true_k5_column=kc.tobytes().hex()))
    # Algorithm 2: R=5 is odd, K4 is the inverse of the official byte-rotation
    # applied to K5. Verify that the retained correct full tuple derives K4.
    full_k5=np.concatenate(true_cols)
    reconstructed_k4=even_from_odd(full_k5)
    if not np.array_equal(full_k5,k[5]) or not np.array_equal(reconstructed_k4,k[4]):
        raise AssertionError('Algorithm 2 K5 -> K4 rotation identity failed')
    # Report how many full tuples survive AMONG THE CANDIDATES EXAMINED,
    # never confuse these with the unenumerated 2^256 terminal space.
    survivor_tuples_examined=1
    for s in sampled_survivors:survivor_tuples_examined*=1+len(s)
    nonweak_balance=None
    if trial<nonweak_controls:
        kw=k.copy()
        kw[0,0]=np.uint8(1+int(rng.integers(0,255)))
        kw[1]=odd_from_even(kw[0])
        outcomes=[]
        for p in ps:
            x=add64(p,kw[0])
            for r in range(1,5):x=F(x)^kw[r]
            outcomes.append(bool(np.all(full_xor(x)==0)))
        nonweak_balance=bool(all(outcomes))
    record=dict(trial=trial,seed=seed,
        distinguisher_passed=True,
        all_32_balanced_bytes=True,correct_K5_columns_retained=correct,
        algorithm2_K4_rotation_verified=True,
        sampled_full_K5_tuples_survived=survivor_tuples_examined,
        wrong_K5_columns_tested=wrong_tested,
        wrong_pass_first=wrong_first,
        wrong_survive_both=wrong_both,
        nonweak_control_balanced_both=nonweak_balance,
        second_structure_offset_byte2=offset,
        exhaustive_msb_differences=exhaustive_msb,
        key_model='synthetic_weak_Kpw_8_zero_rotated_odd_round_keys',
        real_master_key=None,weak_subkey_fraction='2^-64',
        weak_Kpw_positions=list(I_WEAK),
        plaintexts_per_multiset=N,chosen_plaintexts=DATA)
    vectors=None
    if trial==0:
        vectors=dict(official_full_cipher_KAT=verify_primitives(),
            model=record['key_model'],
            weak_kpw_positions=list(I_WEAK),
            round_keys=[z.tobytes().hex() for z in k],
            terminal_K5=k[5].tobytes().hex(),
            derived_K4=reconstructed_k4.tobytes().hex(),
            inverse_shiftrows_sets=I_SETS,
            plaintext_definition='P4(x,y)=F^-1(F(0) xor x e6 xor y e7)',
            safe_offset_byte=OFFSET_BYTE,safe_offset_value=offset,multisets=[])
        for p,(states,ct,preimage) in zip(ps,result):
            x0,x1,x2,x3,x4=states
            vectors['multisets'].append(dict(
                plaintext_xy_0_0=p[0].tobytes().hex(),
                plaintext_xy_0_1=p[1].tobytes().hex(),
                plaintext_xy_1_0=p[256].tobytes().hex(),
                plaintext_xy_255_255=p[-1].tobytes().hex(),
                first_round_preimage_xy_0_0=preimage[0].tobytes().hex(),
                after_prewhitening_xy_0_0=x0[0].tobytes().hex(),
                after_round1_xy_0_0=x1[0].tobytes().hex(),
                after_round2_xy_0_0=x2[0].tobytes().hex(),
                after_round3_xy_0_0=x3[0].tobytes().hex(),
                after_round4_xy_0_0=x4[0].tobytes().hex(),
                after_5_round_terminal_addition_xy_0_0=ct[0].tobytes().hex(),
                xor_round4=full_xor(x4).tobytes().hex(),
                xor_ciphertext=full_xor(ct).tobytes().hex()))
    return record,wrong_survivors,vectors


def main():
    parser=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--trials',type=int,default=1000)
    parser.add_argument('--seed',type=int,default=20261117)
    parser.add_argument('--jobs',type=int,default=4)
    parser.add_argument('--random-wrong',type=int,default=2)
    parser.add_argument('--single-bit-wrong',type=int,default=2)
    parser.add_argument('--msb-differences',type=int,default=2)
    parser.add_argument('--full-msb-trials',type=int,default=5)
    parser.add_argument('--nonweak-controls',type=int,default=100)
    parser.add_argument('--progress-every',type=int,default=25)
    parser.add_argument('--out',default='KALYNA256_256_R5_ACTIVE67_RESULTS')
    parser.add_argument('--resume',action='store_true')
    args=parser.parse_args()
    if not 1<=args.trials<=1000000 or args.jobs<1 or args.progress_every<1 or any(getattr(args,n)<0 for n in ('random_wrong','single_bit_wrong','msb_differences','full_msb_trials','nonweak_controls')):
        parser.error('Invalid count or process arguments')
    out=Path(args.out);out.mkdir(parents=True,exist_ok=True)
    options=dict(trials=args.trials,seed=args.seed,random_wrong=args.random_wrong,
                 single_bit_wrong=args.single_bit_wrong,msb_differences=args.msb_differences,
                 full_msb_trials=args.full_msb_trials,nonweak_controls=args.nonweak_controls)
    source_hash=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    sf=out/'settings.json'
    if args.resume and sf.exists():
        previous=json.loads(sf.read_text())
        if previous['options']!=options or previous['source_sha256']!=source_hash:
            raise ValueError('Refusing resume: configuration or source changed')
    else:
        if (out/'trials.jsonl').exists():raise FileExistsError('Existing output; use --resume')
        sf.write_text(json.dumps(dict(options=options,source_sha256=source_hash,
            reference=REFERENCE,reference_commit=REFERENCE_COMMIT,
            numpy=np.__version__,python=sys.version,platform=platform.platform()),indent=2))
    known_answer=verify_primitives()
    (out/'official_known_answer.json').write_text(json.dumps(known_answer,indent=2))
    completed={}
    if args.resume and (out/'trials.jsonl').exists():
        for ln in (out/'trials.jsonl').read_text().splitlines():
            if ln.strip():
                d=json.loads(ln);completed[d['trial']]=d
    pending=[i for i in range(args.trials) if i not in completed]
    print('Kalyna-256/256: 4R weak-key integral -> 5R Algorithm 2 column filtering',flush=True)
    print('Official full-14R 256/256 encryption/decryption KAT: PASS',flush=True)
    print('Exact P4=F^-1(F0 xor x e6 xor y e7), two complete 2^16 plaintext multisets',flush=True)
    print('8 zero Kpw byte positions:',I_WEAK,flush=True)
    print('Admissible weak Kpw fraction 2^-64; synthetic subkeys; NOT genuine master keys',flush=True)
    print('Terminal K5: modulo addition; K4=EvenFromOdd(K5) for Algorithm 2',flush=True)
    print('Inverse ShiftRows column index sets:',I_SETS,flush=True)
    print(f'Completed {len(completed)}, remaining {len(pending)}',flush=True)
    t0=time.perf_counter()
    def commit(item):
        rec,survivors,vec=item
        if rec['trial'] in completed:return
        completed[rec['trial']]=rec
        with (out/'trials.jsonl').open('a') as f:f.write(json.dumps(rec,sort_keys=True)+'\n')
        if survivors:
            with (out/'wrong_key_survivors.jsonl').open('a') as f:
                for s in survivors:f.write(json.dumps(s,sort_keys=True)+'\n')
        if vec is not None:
            (out/'reproducible_test_vectors.json').write_text(json.dumps(vec,indent=2))
        n=len(completed)
        if n%args.progress_every==0 or n==args.trials:
            correct=sum(t['correct_K5_columns_retained'] for t in completed.values())
            bad=sum(t['wrong_survive_both'] for t in completed.values())
            print(f'Progress {n}/{args.trials}; correct K5 cols {correct}/{4*n}; sampled wrong survivors {bad}; elapsed {time.perf_counter()-t0:.1f}s',flush=True)
    if args.jobs==1:
        for trial in pending:
            commit(run_trial(trial,args.seed,args.random_wrong,args.single_bit_wrong,
                             args.msb_differences,args.full_msb_trials,args.nonweak_controls))
    else:
        with ProcessPoolExecutor(max_workers=args.jobs) as pool:
            futures={pool.submit(run_trial,trial,args.seed,args.random_wrong,args.single_bit_wrong,
                                 args.msb_differences,args.full_msb_trials,args.nonweak_controls):trial
                     for trial in pending}
            for future in as_completed(futures): commit(future.result())
    ordered=[completed[i] for i in range(args.trials)]
    assert all(x['distinguisher_passed'] and x['correct_K5_columns_retained']==4
               and x['algorithm2_K4_rotation_verified'] for x in ordered)
    cols=['trial','seed','key_model','weak_subkey_fraction','chosen_plaintexts',
        'distinguisher_passed','correct_K5_columns_retained','algorithm2_K4_rotation_verified',
        'wrong_K5_columns_tested','wrong_pass_first','wrong_survive_both',
        'sampled_full_K5_tuples_survived','nonweak_control_balanced_both',
        'second_structure_offset_byte2','exhaustive_msb_differences']
    with (out/'trial_summary.csv').open('w',newline='') as f:
        wr=csv.DictWriter(f,fieldnames=cols);wr.writeheader()
        for row in ordered:wr.writerow({k:row.get(k) for k in cols})
    controls=[r['nonweak_control_balanced_both'] for r in ordered if r['nonweak_control_balanced_both'] is not None]
    summary=dict(trials=args.trials,distinguishers_passed=sum(r['distinguisher_passed'] for r in ordered),
        valid_multisets=2*args.trials,plaintexts_per_multiset=N,chosen_plaintexts=DATA,
        balanced_bytes_per_multiset=32,active_positions=list(ACTIVE),weak_kpw_positions=list(I_WEAK),
        safe_offset_byte=OFFSET_BYTE,
        admissible_subkey_fraction='2^-64',admissible_subkeys='2^192',
        correct_K5_columns_retained=sum(r['correct_K5_columns_retained'] for r in ordered),
        correct_K5_columns_expected=4*args.trials,
        K4_derived_by_rotation_on_all_trials=all(r['algorithm2_K4_rotation_verified'] for r in ordered),
        wrong_K5_column_candidates_tested=sum(r['wrong_K5_columns_tested'] for r in ordered),
        wrong_pass_first=sum(r['wrong_pass_first'] for r in ordered),
        wrong_survive_both=sum(r['wrong_survive_both'] for r in ordered),
        sampled_full_K5_tuples_survived_total=sum(r['sampled_full_K5_tuples_survived'] for r in ordered),
        nonweak_controls=len(controls),nonweak_controls_balanced_both=sum(controls),
        nominal_exhaustive_work='2^83 64-bit column partial-decryption operations',
        master_key_schedule_compatibility='NOT ESTABLISHED',
        exhaustive_2power64_column_search=False,full_master_key_recovered=False,
        source_sha256=source_hash,wall_seconds_this_session=round(time.perf_counter()-t0,3))
    (out/'summary.json').write_text(json.dumps(summary,indent=2))
    report='# Kalyna-256/256 — 4-round restricted integral / 5-round filtering\n\n'
    report+='\n'.join(f'- **{k}**: {v}' for k,v in summary.items())
    report+='''

## Exact assumptions and referee scope
Updated Table 2 (Kalyna-256/256, R=5): 2^17 chosen texts, nominal
2^83 **64-bit column partial-decryption operations**, Algorithm 2,
weak pre-whitening subkey fraction 2^-64. The two multisets use
P4(x,y)=F^-1(F(0) xor x*e6 xor y*e7), plus a nonzero byte-2
translation above the variable positions 0 and 1 in the first column.
The exact common inverse support is I={0,1,14,15,20,21,26,27}.
The eight key bytes in I are fixed to zero (a sufficient condition),
leaving 2^192 admissible pre-whitening subkeys. All remaining bytes
are unrestricted. For the second multiset, carries from the offset
can affect only constant bytes; the variable bytes are unchanged.
These are restrictions on the subkey, NOT proven conditions on master keys.
Odd/even rotation identities K1=Rot(K0), K3=Rot(K2), K5=Rot(K4) are
employed. For the odd terminal round R=5, Algorithm 2 gives
K4=Rot^-1(K5) once a complete K5 candidate is assembled.

The 4-round integral is checked at INTERNAL X4 (before terminal modular
addition). The 5R ciphertexts are generated using
C=F(X4) boxplus K5, and the filter uses full 64-bit modular subtraction
and bytewise inverse-S-box sums in each inverse-SR column index set.
The correct complete K5 -> K4 rotation is verified.
All 28 X2 output pairs are tested for joint uniformity; Appendix B.3
byte formula and exact first-round identities are checked pointwise.
Candidate filtering is NOT exhaustive and cannot establish key uniqueness
in the full 2^256 terminal keyspace. This program does not derive the
master key or calculate a full-encryption-equivalent runtime.
All incorrect candidates are sampled or structured: random columns,
single-bit changes, MSB-byte changes, and modular-addition differences.
Nonweak controls document violation of a sufficient condition, not a
mathematical necessity of failure for every restricted-key violation.
'''
    (out/'REPORT.md').write_text(report)
    print('COMPLETE',json.dumps(summary,indent=2),flush=True)
    return 0

if __name__=='__main__':
    raise SystemExit(main())
