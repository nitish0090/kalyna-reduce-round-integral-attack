#!/usr/bin/env python3
"""Kalyna-256/512: EXACT 4-round conditional integral -> 6-round filtering.

Updated manuscript Section 4.3 & Section 6 Algorithm 4, Table 2.
P4(x,y)=F^-1(F(0) xor x e7 xor y e24), all (x,y) in GF(256)^2.
Two valid, disjoint 2^16 plaintext multisets; 2^17 total chosen texts.
Weak Kpw bytes MUST vanish on I={0,1,6,7,12,13,14,15,18,19,20,21,24,25,26,27}.
Subkey-space fraction 2^-128. Synthetic restricted round subkeys, with
all mandatory K(odd)=RotL_88(K(odd-1)) relations; NOT verified real master keys.

At X4 (internal XOR-keyed round), all 32 bytes balance. Then R6 has
X5=F(X4) xor K5, C=F(X5) boxplus K6 (64-bit little-endian columns).
Algorithm 4 filters full 256-bit K6 guesses against all 256 equivalent
K5-byte guesses independently; ALL survivor sets are retained, including
nonunique candidates. Derive K4=RotR_88(K5) for a surviving K5.
No exhaustive 2^256 enumeration and no master key recovery claim.
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

VERSION = '1.0'
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
ROUNDS = 18
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
    """Exact 256/512 Kalyna schedule, 19 x 256-bit subkeys K[0]..K[18]."""
    key=a8(master)
    if key.shape!=(64,): raise ValueError('512-bit key required')
    s=np.zeros(32,dtype=np.uint8)
    s[0]=4+8+1
    kt=F(add64(F(F(add64(s,key[:32]))^key[32:]),key[:32]))
    keys=np.empty((19,32),dtype=np.uint8)
    tmv=np.tile(np.array([1,0,1,0,1,0,1,0],dtype=np.uint8),4)
    data=key.copy()
    r=0
    while True:
        tmp=add64(kt,tmv)
        keys[r]=add64(F(F(add64(data[:32],tmp))^tmp),tmp)
        if r==18: break
        r+=2
        tmv=add64(tmv,tmv)
        tmp=add64(kt,tmv)
        keys[r]=add64(F(F(add64(data[32:],tmp))^tmp),tmp)
        if r==18: break
        r+=2
        tmv=add64(tmv,tmv)
        data=np.roll(data,-8)  # official Rotate: one 64-bit word over 8 words
    for r in range(1,18,2):
        keys[r]=odd_from_even(keys[r-1])
    return keys




# ============================================================================
# Official vectors, genuine encryption and two-round distinguisher
# ============================================================================
TEST_CT = '606990e9e6b7b67a4bd6d893d72268b78e02c83c3cd7e102fd2e74a8fdfe5dd9'
def xorsum(v):return np.bitwise_xor.reduce(a8(v),axis=-2)

TEST_CT = '606990e9e6b7b67a4bd6d893d72268b78e02c83c3cd7e102fd2e74a8fdfe5dd9'
def xorsum(v):return np.bitwise_xor.reduce(a8(v),axis=-2)

DATA_PER_MULTISET = 256
D = 512
G_VALUES = np.arange(256,dtype=np.uint8)


def encrypt_full(p, keys):
    assert keys.shape==(19,32)
    x=add64(p,keys[0])
    for r in range(1,18):x=F(x)^keys[r]
    return add64(F(x),keys[18])


def decrypt_full(c,keys):
    x=Finv(sub64(c,keys[18]))
    for r in range(17,0,-1):x=Finv(x^keys[r])
    return sub64(x,keys[0])


def test_core():
    master=np.arange(64,dtype=np.uint8)
    plain=np.arange(64,96,dtype=np.uint8)
    keys=expand_key(master)
    actual=encrypt_full(plain,keys).tobytes().hex()
    if actual!=TEST_CT:
        raise AssertionError(f'Official 256/512 KAT FAIL: got {actual}; expected {TEST_CT}')
    if not np.array_equal(decrypt_full(np.frombuffer(bytes.fromhex(TEST_CT),dtype=np.uint8),keys),plain):
        raise AssertionError('Official 256/512 KAT decryption FAIL')
    assert np.array_equal(keys[3],odd_from_even(keys[2]))
    rng=np.random.default_rng(20261117)
    for _ in range(10):
        v=rng.integers(0,256,(5,32),dtype=np.uint8)
        k=rng.integers(0,256,32,dtype=np.uint8)
        assert np.array_equal(Finv(F(v)),v)
        assert np.array_equal(sub64(add64(v,k),k),v)
        assert np.array_equal(even_from_odd(odd_from_even(k)),k)
    assert set(I_SETS[0])=={0,1,14,15,20,21,26,27}
    return dict(official_256_512_encryption='PASS',official_256_512_decryption='PASS',
                ciphertext=TEST_CT,master_key=master.tobytes().hex(),
                plaintext=plain.tobytes().hex(),
                F_inverse='PASS',modular_borrow='PASS',K3_K2_rotation='PASS')



from functools import lru_cache

VERSION = '1.0'
I_X = (0,1,14,15,20,21,26,27)
I_Y = (6,7,12,13,18,19,24,25)
I_WEAK = tuple(sorted(I_X+I_Y))
ACTIVE = (7,24)
N = 1 << 16
DATA = 2*N
OFFSET_BYTE = 28
ZERO = np.zeros(32, dtype=np.uint8)
BYTE_GUESSES = np.arange(256,dtype=np.uint8)


@lru_cache(maxsize=1)
def p4_base():
    """Exact, cached, key-INDEPENDENT plaintext multiset."""
    t=np.broadcast_to(F(ZERO),(N,32)).copy()
    t[:,7] ^= np.repeat(BYTE_GUESSES,256)
    t[:,24] ^= np.tile(BYTE_GUESSES,256)
    p=Finv(t)
    assert np.array_equal(F(p),t), 'P4 preimage identity failed'
    assert np.all(p[:,list(set(range(32))-set(I_WEAK))]==0)
    p.flags.writeable=False
    return p


def plaintext_structures(rng):
    p0=p4_base()
    a=int(rng.integers(1,256))
    p1=p0.copy()
    p1[:,OFFSET_BYTE] ^= np.uint8(a)
    assert not np.any(p0[:,OFFSET_BYTE])
    assert np.all(p1[:,OFFSET_BYTE]==a)
    return (p0,p1),a


def subkeys_restricted(rng):
    """Synthetic round keys, NOT claimed to follow full nonlinear schedule."""
    k=rng.integers(0,256,(7,32),dtype=np.uint8)
    k[0,list(I_WEAK)]=0
    for odd in (1,3,5):k[odd]=odd_from_even(k[odd-1])
    assert all(np.array_equal(k[odd],odd_from_even(k[odd-1])) for odd in (1,3,5))
    return k


def full_product_two_byte(array,indices=ACTIVE):
    code=array[:,indices[0]].astype(np.uint32)*256+array[:,indices[1]].astype(np.uint32)
    counts=np.bincount(code,minlength=N)
    return bool(counts.size==N and np.all(counts==1))


def forward_6rounds(p,k):
    x0=add64(p,k[0])
    x1=F(x0)^k[1]
    x2=F(x1)^k[2]
    x3=F(x2)^k[3]
    x4=F(x3)^k[4]
    x5=F(x4)^k[5]
    c=add64(F(x5),k[6])
    return (x0,x1,x2,x3,x4,x5),c


def check_distinguisher(ps,k,a):
    assert k.shape==(7,32)
    assert np.all(k[0,list(I_WEAK)]==0)
    assert all(np.array_equal(k[i],odd_from_even(k[i-1])) for i in (1,3,5))
    outcomes=[]
    for j,p in enumerate(ps):
        assert p.shape==(N,32)
        assert np.all(p[:,OFFSET_BYTE]==(a if j==1 else 0))
        # Verify the two-variable representation at F(p), with fixed constants.
        fp=F(p)
        t=fp.copy();t[:,list(ACTIVE)]=0
        assert np.array_equal(t,np.broadcast_to(t[0],t.shape)), 'Translated P4 lost exact structure'
        assert full_product_two_byte(fp), 'Not a complete Cartesian product'
        states,c=forward_6rounds(p,k)
        x0,x1,x2,x3,x4,x5=states
        delta=x0^p
        assert np.all(delta==delta[0]), 'Variable modular pre-whitening carry'
        assert not np.any(delta[:,list(I_WEAK)]), 'Active input bytes changed in PW'
        tmp=x1.copy();tmp[:,list(ACTIVE)]=0
        assert np.all(tmp==tmp[0]), 'First round not exact two-byte product'
        assert full_product_two_byte(x1)
        assert np.all(x2[:,:24]==x2[0,:24]), 'Unexpected X2 active columns'
        for i in range(24,32):
            assert np.all(np.bincount(x2[:,i],minlength=256)==256), ('X2 All',i)
        assert full_product_two_byte(x2,(24,31)), 'Missing pairwise All property'
        for i in range(32):
            assert np.all(np.bincount(x3[:,i],minlength=256)==256), ('X3 All',i)
        assert not np.any(xorsum(x4)), 'X4 not balanced'
        # EXACT inverse checks, independent of the partial-key filter.
        assert np.array_equal(Finv(sub64(c,k[6])),x5), 'Terminal inverse failed'
        assert np.array_equal(Finv(x5^k[5]),x4), 'Second inverse failed'
        outcomes.append((states,c,fp))
    return outcomes


def L_inverse(x):
    """L^-1(X) = SR^-1(MC^-1(X)); full 256-bit state essential."""
    return mix(a8(x),True)[...,IS]


def L_forward(x):
    return mix(a8(x)[...,SR])


def byte_candidates(y0,y1,row):
    """EXACT parity-compressed inverse-S-box XOR test, all 256 g."""
    allowed=np.ones(256,dtype=bool)
    for y in (y0,y1):
        odd=np.flatnonzero(np.bincount(y,minlength=256)&1).astype(np.uint8)
        if odd.size:
            values=INV_SBOX[row, odd[:,None]^BYTE_GUESSES[None,:]]
            s=np.bitwise_xor.reduce(values,axis=0)
            allowed&=s==0
        if not np.any(allowed):return np.empty(0,dtype=np.uint8)
    return BYTE_GUESSES[allowed]


def prepare_outer_y(c,k6):
    # C = F(X5) boxplus K6; u = X5; y=L^-1(u)=SB(X4) xor L^-1(K5).
    return L_inverse(Finv(sub64(c,k6)))


def filter_full_K6(cts,guess,first_only=False):
    """Algorithm 4. Never insert any correct-key guess as a forced survivor.

    Wrong keys: evaluate first COMPLETE multiset; early reject when any
    equivalent K5 byte has empty candidate set. Only then evaluate second.
    """
    y0=prepare_outer_y(cts[0],guess)
    ys=(y0,) if first_only else (y0,prepare_outer_y(cts[1],guess))
    G=[]
    for i in range(32):
        s=byte_candidates(ys[0][:,i],ys[-1][:,i],i%4) if len(ys)==2 else byte_candidates(ys[0][:,i],ys[0][:,i],i%4)
        if not s.size:return None,i
        G.append(s)
    return G,32


def wrong_terminal_candidates(true_k6,rng,trial,random_wrong,singlebit,msb,carry,full_msb=False):
    found={}
    key=true_k6.tobytes()
    def add(v,typ):
        z=a8(v).tobytes()
        if z!=key:found.setdefault(z,typ)
    for _ in range(random_wrong):add(rng.integers(0,256,32,dtype=np.uint8),'random')
    for z in range(singlebit):
        v=true_k6.copy();bit=(trial*127+z*41)%256
        v[bit//8]^=np.uint8(1<<(bit%8));add(v,'single-bit')
    for z in range(255 if full_msb else msb):
        v=true_k6.copy();idx=7+8*((trial+z)%4)
        v[idx]^=np.uint8(1+(z if full_msb else (trial*13+z*29)%255))
        add(v,'MSB-byte')
    for j in range(carry):
        col=(trial+j)%4
        q=true_k6.copy()
        n=int.from_bytes(q[8*col:8*col+8].tobytes(),'little')
        d=(1,-1,1<<56,1<<63)[j%4]
        q[8*col:8*col+8]=np.frombuffer(((n+d)%(1<<64)).to_bytes(8,'little'),dtype=np.uint8)
        add(q,'modular-carry')
    return [(np.frombuffer(z,dtype=np.uint8).copy(),typ) for z,typ in sorted(found.items())]


def trial_run(trial,seed,random_wrong,singlebit,msb,carry,wrong_trials,full_msb_trials,nonweak_controls):
    rng=np.random.default_rng(np.random.SeedSequence([seed,trial,2565126]))
    k=subkeys_restricted(rng)
    ps,offset=plaintext_structures(rng)
    outcome=check_distinguisher(ps,k,offset)
    cts=[v[1] for v in outcome]
    true_tilde=L_inverse(k[5])
    G,idx=filter_full_K6(cts,k[6])
    if G is None:raise AssertionError(('Correct K6 eliminated',trial,idx))
    if not all(int(true_tilde[i]) in g for i,g in enumerate(G)):
        raise AssertionError('Correct equivalent K5 filtered out')
    reconstructed_k5=L_forward(true_tilde)
    reconstructed_k4=even_from_odd(reconstructed_k5)
    assert np.array_equal(reconstructed_k5,k[5]), 'Equivalent K5 reconstruction'
    assert np.array_equal(reconstructed_k4,k[4]), 'K5 -> K4 rotation'
    # Independent exact-pointwise reconstruction of X4 from real equivalent key.
    for (states,c,fp) in outcome:
        x4=INV_SBOX[np.arange(32)%4,prepare_outer_y(c,k[6])^true_tilde]
        assert np.array_equal(x4,states[4]), 'Equivalent partial decryption not pointwise exact'
    sz=1
    for g in G:sz*=len(g)
    wrong_first=0;wrong_final=0;wrong_tested=0;by_category={};survivors=[]
    if trial<wrong_trials:
        wrongs=wrong_terminal_candidates(k[6],rng,trial,random_wrong,singlebit,msb,carry,trial<full_msb_trials)
        for candidate,typ in wrongs:
            wrong_tested+=1;by_category[typ]=by_category.get(typ,0)+1
            g1,idx1=filter_full_K6([cts[0],cts[0]],candidate,first_only=True)
            if g1 is None:continue
            wrong_first+=1
            gall,idx2=filter_full_K6(cts,candidate)
            if gall is not None:
                wrong_final+=1
                survivors.append(dict(trial=trial,type=typ,K6=candidate.tobytes().hex(),
                                      candidate_byte_sizes=[len(z) for z in gall]))
    nonweak=None
    if trial<nonweak_controls:
        bad=k.copy();bad[0,0]=np.uint8(int(rng.integers(1,256)))
        bad[1]=odd_from_even(bad[0])
        res=[]
        for p in ps:
            xx=add64(p,bad[0])
            for i in range(1,5):xx=F(xx)^bad[i]
            res.append(not np.any(xorsum(xx)))
        nonweak=bool(all(res))
    record=dict(trial=trial,seed=seed,
                distinguisher_passed=True,plaintexts_per_multiset=N,chosen_plaintexts=DATA,
                correct_K6_retained=True,correct_equivalent_K5_retained=True,
                correct_K4_derived=True,extra_equivalent_K5_candidates=sz-1,
                equivalent_K5_candidate_count=str(sz),
                equivalent_K5_byte_sizes=[len(z) for z in G],
                wrong_full_K6_tested=wrong_tested,wrong_pass_first=wrong_first,
                wrong_survive_both=wrong_final,wrong_by_category=by_category,
                nonweak_control_passed=nonweak,second_offset_byte28=offset,
                key_model='synthetic_weak_Kpw_16_zero_with_odd_rotations',
                actual_master_key=None,weak_subkey_fraction='2^-128',
                weak_zero_indices=list(I_WEAK))
    vectors=None
    if trial==0:
        vectors=dict(official_known_answer=test_core(),model=record['key_model'],
                no_genuine_master_key_claim=True,zero_Kpw_positions=list(I_WEAK),
                K0_to_K6=[v.tobytes().hex() for v in k],
                true_equivalent_K5=true_tilde.tobytes().hex(),
                equivalent_byte_candidate_sets=[g.tolist() for g in G],
                derived_K4=reconstructed_k4.tobytes().hex(),
                inverse_shiftrows_sets=[list(x) for x in I_SETS],
                exact_input='F^-1(F(0) xor x*e7 xor y*e24)',
                offset_in_byte28=offset,multisets=[])
        for p,(states,c,preimage) in zip(ps,outcome):
            vectors['multisets'].append(dict(
                P_0_0=p[0].tobytes().hex(),P_0_1=p[1].tobytes().hex(),
                P_1_0=p[256].tobytes().hex(),P_255_255=p[-1].tobytes().hex(),
                F_P_0_0=preimage[0].tobytes().hex(),
                X0_0_0=states[0][0].tobytes().hex(),
                X1_0_0=states[1][0].tobytes().hex(),
                X2_0_0=states[2][0].tobytes().hex(),
                X3_0_0=states[3][0].tobytes().hex(),
                X4_0_0=states[4][0].tobytes().hex(),
                X5_0_0=states[5][0].tobytes().hex(),
                C_0_0=c[0].tobytes().hex(),
                xor_X4=xorsum(states[4]).tobytes().hex(),
                xor_C=xorsum(c).tobytes().hex()))
    return record,survivors,vectors


def main():
    parser=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--trials',type=int,default=1000)
    parser.add_argument('--seed',type=int,default=20261117)
    parser.add_argument('--jobs',type=int,default=4)
    parser.add_argument('--wrong-trials',type=int,default=100,help='Only first N trials evaluate incorrect full 256-bit K6 guesses')
    parser.add_argument('--random-wrong',type=int,default=1)
    parser.add_argument('--single-bit-wrong',type=int,default=1)
    parser.add_argument('--msb-differences',type=int,default=1)
    parser.add_argument('--carry-differences',type=int,default=1)
    parser.add_argument('--full-msb-trials',type=int,default=0)
    parser.add_argument('--nonweak-controls',type=int,default=10)
    parser.add_argument('--progress-every',type=int,default=50)
    parser.add_argument('--out',default='KALYNA256_512_R6_RESULTS')
    parser.add_argument('--resume',action='store_true')
    args=parser.parse_args()
    if args.jobs<1 or args.trials<1 or args.progress_every<1 or any(getattr(args,s)<0 for s in
        ('wrong_trials','random_wrong','single_bit_wrong','msb_differences','carry_differences','full_msb_trials','nonweak_controls')):
        parser.error('Invalid count or process arguments')
    out=Path(args.out);out.mkdir(parents=True,exist_ok=True)
    exe=Path(__file__);digest=hashlib.sha256(exe.read_bytes()).hexdigest()
    config={k:getattr(args,k) for k in ('trials','seed','wrong_trials','random_wrong','single_bit_wrong',
        'msb_differences','carry_differences','full_msb_trials','nonweak_controls')}
    settings=out/'settings.json'
    if args.resume:
        if not settings.is_file():raise FileNotFoundError('Missing settings for resume')
        old=json.loads(settings.read_text())
        if old['configuration']!=config or old['source_sha256']!=digest:
            raise ValueError('Resume configuration/source digest mismatch')
    else:
        if settings.exists() or (out/'trials.jsonl').exists():
            raise FileExistsError('Previous run present: select new --out or use --resume')
        settings.write_text(json.dumps(dict(configuration=config,source_sha256=digest,
            reference=REFERENCE,reference_commit=REFERENCE_COMMIT,
            platform=platform.platform(),numpy=np.__version__,python=sys.version),indent=2))
    official=test_core()
    (out/'official_known_answer.json').write_text(json.dumps(official,indent=2))
    records={}
    if args.resume and (out/'trials.jsonl').exists():
        for line in (out/'trials.jsonl').read_text().splitlines():
            if line.strip():
                rec=json.loads(line);records[rec['trial']]=rec
    pending=[t for t in range(args.trials) if t not in records]
    t0=time.perf_counter()
    print('Kalyna-256/512 6R: 4R weak-prewhitening integral -> Algorithm4',flush=True)
    print('P4=F^-1(F0 xor x*e7 xor y*e24), 2 x 65536 structures; Kpw zeros:',I_WEAK,flush=True)
    print('Synthetic restricted subkeys, odd rotations exact, NO genuine-master-key claim',flush=True)
    print('Official full-cipher KAT: PASS.  Nominal 2^286 inverse S-box operations, NOT encryptions',flush=True)
    print(f'Completed {len(records)}, outstanding {len(pending)}',flush=True)
    def commit(result):
        rec,survivors,vectors=result
        if rec['trial'] in records:return
        records[rec['trial']]=rec
        with (out/'trials.jsonl').open('a') as f:f.write(json.dumps(rec,sort_keys=True)+'\n')
        if survivors:
            with (out/'wrong_full_K6_survivors.jsonl').open('a') as f:
                for s in survivors:f.write(json.dumps(s,sort_keys=True)+'\n')
        if vectors is not None:(out/'reproducible_test_vectors.json').write_text(json.dumps(vectors,indent=2))
        n=len(records)
        if n%args.progress_every==0 or n==args.trials:
            print(f'Progress {n}/{args.trials}; true K6 {sum(v["correct_K6_retained"] for v in records.values())}; '
                f'wrong {sum(v["wrong_full_K6_tested"] for v in records.values())}; '
                f'wrong survived {sum(v["wrong_survive_both"] for v in records.values())}; '
                f'elapsed {time.perf_counter()-t0:.1f}s',flush=True)
    parameters=(args.seed,args.random_wrong,args.single_bit_wrong,args.msb_differences,
                args.carry_differences,args.wrong_trials,args.full_msb_trials,args.nonweak_controls)
    if args.jobs==1:
        for trial in pending:commit(trial_run(trial,*parameters))
    else:
        with ProcessPoolExecutor(max_workers=args.jobs) as pool:
            future_map={pool.submit(trial_run,trial,*parameters):trial for trial in pending}
            for future in as_completed(future_map):commit(future.result())
    ordered=[records[i] for i in range(args.trials)]
    assert all(q['distinguisher_passed'] and q['correct_K6_retained'] and
               q['correct_equivalent_K5_retained'] and q['correct_K4_derived'] for q in ordered)
    cols=['trial','seed','chosen_plaintexts','distinguisher_passed','correct_K6_retained',
          'correct_equivalent_K5_retained','correct_K4_derived','extra_equivalent_K5_candidates',
          'equivalent_K5_candidate_count','wrong_full_K6_tested','wrong_pass_first','wrong_survive_both',
          'nonweak_control_passed','second_offset_byte28']
    with (out/'trial_summary.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=cols);writer.writeheader()
        for row in ordered:writer.writerow({s:row.get(s) for s in cols})
    category_counts={}
    for row in ordered:
        for cat,n in row['wrong_by_category'].items():category_counts[cat]=category_counts.get(cat,0)+n
    controls=[q['nonweak_control_passed'] for q in ordered if q['nonweak_control_passed'] is not None]
    summ=dict(trials=len(ordered),distinguishers_passed=sum(q['distinguisher_passed'] for q in ordered),
        validated_multisets=2*len(ordered),balanced_bytes_per_multiset=32,
        plaintexts_per_multiset=N,chosen_plaintexts_per_trial=DATA,
        correct_K6_retained=sum(q['correct_K6_retained'] for q in ordered),
        correct_equivalent_K5_retained=sum(q['correct_equivalent_K5_retained'] for q in ordered),
        K4_derived=sum(q['correct_K4_derived'] for q in ordered),
        trials_with_extra_equivalent_K5_candidates=sum(q['extra_equivalent_K5_candidates']>0 for q in ordered),
        additional_equivalent_K5_candidates=sum(q['extra_equivalent_K5_candidates'] for q in ordered),
        wrong_full_K6_tested=sum(q['wrong_full_K6_tested'] for q in ordered),
        wrong_pass_first=sum(q['wrong_pass_first'] for q in ordered),
        wrong_survive_both=sum(q['wrong_survive_both'] for q in ordered),
        wrong_candidate_types=category_counts,
        nonweak_controls=len(controls),nonweak_controls_balanced_both=sum(controls),
        zero_Kpw_positions=list(I_WEAK),weak_subkey_fraction='2^-128',
        weak_subkey_values='2^128 of 2^256',
        key_model='synthetic restricted subkeys, all odd/even rotations enforced',
        official_full_cipher_KAT='PASS',nominal_work='2^286 inverse S-box evaluations (NOT encryptions)',
        exhaustive_K6_enumeration=False,complete_master_key_recovered=False,
        source_sha256=digest,wall_seconds_this_session=round(time.perf_counter()-t0,3))
    (out/'summary.json').write_text(json.dumps(summ,indent=2))
    r='# Kalyna-256/512 — 4-round conditional integral -> 6-round Algorithm 4\n\n'
    r+='\n'.join(f'- **{k}**: {v}' for k,v in summ.items())
    r+='''\n\n## Exact construction and weak-subkey restrictions\nP4(x,y)=F^-1(F(0) xor x e7 xor y e24). All 65536 (x,y) pairs.\nThe second multiset is a fixed nonzero e28 translation (disjoint, safe\nabove the input-dependent positions in its column). Kpw[i]=0 for\ni={0,1,6,7,12,13,14,15,18,19,20,21,24,25,26,27}.\nThe resulting 2^-128 admissible fraction applies to freely specified\npre-whitening SUBKEYS. This script does not show that a genuine 512-bit\nmaster-key expansion can satisfy the restriction.\n\n## Round convention and Algorithm 4\nThe distinguisher is checked at internal XOR-keyed X4, BEFORE modular\nterminal addition. The 6R model computes X5=F(X4) xor K5 and\nC=F(X5) boxplus K6 with four independent 64-bit modular additions.\nFor a guessed full K6, calculate U=F^-1(C boxminus K6) and Y=L^-1(U).\nFor every byte i retain ALL g such that xor S^-1_i(Y[i] xor g)=0 on\neach of TWO complete multisets. This is the exact Algorithm 4 test.\nThe correct tilde K5=L^-1(K5) is verified, and K4=RotR_88(K5)\nis checked. Equivalent-key survivors are retained, never forced unique.\n\n## Limits of evidence\nIncorrect full K6 guesses are sampled, not enumerated over 2^256.\nThe nominal work 2^286 counts Sbox inversions, plus uncounted\npreprocessing and Cartesian survivor combination; it is not full\nencryptions. This script does NOT recover a genuine master key or prove\nuniqueness. Nonweak controls test a sufficient condition only.\n'''
    (out/'REPORT.md').write_text(r)
    print('COMPLETE\n'+json.dumps(summ,indent=2),flush=True)
    return 0


if __name__=='__main__':raise SystemExit(main())
