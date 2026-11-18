#!/usr/bin/env python3
"""Kalyna-256/512: 2-round integral distinguisher + 4-round Algorithm 4 filtering.

Uses authentic 512-bit master keys and the official 256-bit state/key schedule,
pre-whitening with addition modulo 2^64, two XOR-keyed internal rounds and
last-round modular addition. Two COMPLETE, DISJOINT multisets of 256 plaintexts.

Correct K4 is verified by 2-round partial decryption followed by equivalent
K3-byte candidate sets G_i, retaining ALL members (no |G_i| = 1 assumption).
For sampled WRONG K4 guesses, early rejection if any G_i is empty.
None of these tests searches the full 2^256 space or recovers a master key.

This is experimental validation for the Table 2 Kalyna-256/512 R=4 entry;
counts are not full-encryption equivalents.
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


def plaintext_structures(rng):
    """P(x)=a xor x e7; second multiset shifts fixed byte 4 by nonzero value."""
    a=rng.integers(0,256,32,dtype=np.uint8)
    a[7]=0
    p=np.tile(a,(256,1))
    p[:,7]=G_VALUES
    off=int(rng.integers(1,256))
    q=p.copy()
    q[:,4]^=np.uint8(off)
    return (p,q),off


def forward_2dist_4target(p,k):
    x0=add64(p,k[0]);x1=F(x0)^k[1];x2=F(x1)^k[2]
    x3=F(x2)^k[3]
    ciphertext=add64(F(x3),k[4])
    return (x0,x1,x2,x3),ciphertext


def check_distinguisher(ps,k):
    if not np.array_equal(k[3],odd_from_even(k[2])):raise AssertionError('K3 rotation')
    if int(ps[0][0,4])==int(ps[1][0,4]):raise AssertionError('identical multisets')
    outcomes=[]
    for p in ps:
        assert p.shape==(256,32)
        if not np.array_equal(p[:,7],G_VALUES):raise AssertionError('wrong input x')
        if np.any(p[:,[i for i in range(32) if i!=7]]!=p[0,[i for i in range(32) if i!=7]]):
            raise AssertionError('nonactive input not constant')
        states,c=forward_2dist_4target(p,k)
        x0,x1,x2,x3=states
        for i in range(32):
            nuniq=len(np.unique(x0[:,i]))
            if nuniq!=(256 if i==7 else 1):
                raise AssertionError(('prewhitening A/C',i,nuniq))
        for i in range(32):
            nuniq=len(np.unique(x1[:,i]))
            if nuniq!=(256 if 24<=i<32 else 1):
                raise AssertionError(('round 1 A/C',i,nuniq))
        sums=xorsum(x2)
        if np.any(sums):raise AssertionError(('round2 balance failure',sums.tolist()))
        if not np.array_equal(Finv(sub64(c,k[4])),x3):
            raise AssertionError('first terminal inverse not pointwise correct')
        if not np.array_equal(Finv(x3^k[3]),x2):
            raise AssertionError('second keyed inverse not pointwise correct')
        outcomes.append((states,c))
    return outcomes


def linear_inverse(x):
    """L^{-1} = InvSR o InvMC; inverse SR acts on full 32-byte state."""
    return mix(a8(x),True)[...,IS]


def equivalent_true_key(k3):
    return linear_inverse(k3)


def candidate_g_for_byte(y0,y1,row):
    """All g in GF(256) passing two XOR sums, including multi-candidate cases.

    Uses parity of the occurrences of Y_i: each even multiplicity cancels
    before Sbox inverse, independently for each trial g. This is EXACT, not
    a statistical shortcut.
    """
    allowed=np.ones(256,dtype=bool)
    for y in (y0,y1):
        odd=np.flatnonzero((np.bincount(y,minlength=256)&1)!=0).astype(np.uint8)
        if len(odd):
            values=INV_SBOX[row, np.bitwise_xor(odd[:,None],G_VALUES[None,:])]
            sums=np.bitwise_xor.reduce(values,axis=0)
            allowed&=(sums==0)
        if not np.any(allowed):return np.empty(0,dtype=np.uint8)
    return G_VALUES[allowed]


def filter_outer_guess(ciphertexts,guess_k4):
    """Algorithm 4: guessed K4 -> inverse terminal -> inverse MC/SR -> G_i.

    Returns candidate sets; abort early when a byte has no candidate.
    The function NEVER inserts the genuine key by construction.
    """
    ys=[]
    for c in ciphertexts:
        u=Finv(sub64(c,guess_k4))      # X3 when outer guess correct
        y=linear_inverse(u)             # L^{-1}(X3)
        ys.append(y)
    G=[]
    for i in range(32):
        matches=candidate_g_for_byte(ys[0][:,i],ys[1][:,i],i%4)
        if len(matches)==0:return None,i
        G.append(matches)
    return G,32


def verify_equivalent_enumeration(cts,k):
    """At correct K4 retain ALL per-byte survivors; check genuine equiv K3.

    Enumerate Cartesian product only when manageable; do not invent uniqueness.
    For huge products, retain factorized G_i and exact cardinality.
    """
    G,position=filter_outer_guess(cts,k[4])
    if G is None:raise AssertionError(('correct K4 rejected at byte',position))
    tilde=equivalent_true_key(k[3])
    for i,poss in enumerate(G):
        if int(tilde[i]) not in poss:
            raise AssertionError(('correct equivalent K3 BYTE rejected',i,int(tilde[i])))
    # Additional independent check: inversion yields the true X2 for the
    # complete multisets, not just XOR sums.
    for c in cts:
        u=Finv(sub64(c,k[4]))
        x2candidate=INV_SBOX[np.arange(32)%4,linear_inverse(u)^tilde]
        original=Finv(u^k[3])
        if not np.array_equal(x2candidate,original):
            raise AssertionError('equivalent key inverse is not pointwise exact')
        if np.any(xorsum(x2candidate)):
            raise AssertionError('correct candidate not balanced')
    size=1
    for v in G:size*=len(v)
    # Rotation derivation uses K3=RotateLeft_88(K2), so K2=RotateRight_88(K3).
    reconstructed_k3=mix(tilde[...,SR],False)  # L(tilde)
    if not np.array_equal(reconstructed_k3,k[3]):raise AssertionError('K3 reconstruction')
    if not np.array_equal(even_from_odd(reconstructed_k3),k[2]):raise AssertionError('K2 rotation')
    return G,size


def wrong_outer_candidates(truekey,rng,trial,random_wrong,single_bit_wrong,msb_differences,full_msb):
    """Sample 256-bit FULL K4 keys; distinguish from 64-bit column candidates.

    All differences are nonzero; deduplicated within each trial.
    """
    answer=set()
    truebytes=truekey.tobytes()
    def add(q):
        b=a8(q).tobytes()
        if b!=truebytes:answer.add(b)
    for _ in range(random_wrong):
        add(rng.integers(0,256,32,dtype=np.uint8))
    for j in range(min(single_bit_wrong,256)):
        q=truekey.copy();bit=(trial*39+j*37)%256
        q[bit//8]^=np.uint8(1<<(bit%8));add(q)
    if full_msb:
        for col in range(4):
            for delta in range(1,256):
                q=truekey.copy();q[8*col+7]^=np.uint8(delta);add(q)
    else:
        for col in range(4):
            for j in range(min(msb_differences,255)):
                q=truekey.copy();q[8*col+7]^=np.uint8(1+(trial*17+col*11+j*13)%255);add(q)
    for col in range(4):
        val=int.from_bytes(truekey[8*col:8*col+8].tobytes(),'little')
        for d in (1,-1,1<<56,1<<63):
            q=truekey.copy()
            q[8*col:8*col+8]=np.frombuffer(((val+d)%(1<<64)).to_bytes(8,'little'),dtype=np.uint8)
            add(q)
    return [np.frombuffer(q,dtype=np.uint8).copy() for q in sorted(answer)]


def run_trial(t,seed,random_wrong,single_bit_wrong,msb_differences,full_msb_trials):
    rng=np.random.default_rng(np.random.SeedSequence([int(seed),int(t),2565124]))
    master=rng.integers(0,256,64,dtype=np.uint8)
    k=expand_key(master)
    ps,offset=plaintext_structures(rng)
    outcomes=check_distinguisher(ps,k)
    cts=[x[1] for x in outcomes]
    G,size=verify_equivalent_enumeration(cts,k)
    # An independent direct evaluation of the balance for a few g values.
    if t==0:
        z=linear_inverse(Finv(sub64(cts[0],k[4])))
        for i in (0,7,15,24,31):
            for g in (0,1,13,255):
                actual=int(np.bitwise_xor.reduce(INV_SBOX[i%4,z[:,i]^np.uint8(g)]))
                # Not a two-multiset condition; separately match first multiset.
                odd=np.flatnonzero(np.bincount(z[:,i],minlength=256)&1).astype(np.uint8)
                parity=int(np.bitwise_xor.reduce(INV_SBOX[i%4,odd^np.uint8(g)])) if len(odd) else 0
                if actual!=parity:raise AssertionError('parity optimization incorrect')
    wrong=wrong_outer_candidates(k[4],rng,t,random_wrong,single_bit_wrong,msb_differences,t<full_msb_trials)
    wrong_pass=[];total=0
    for guess in wrong:
        sets,reached=filter_outer_guess(cts,guess)
        total+=1
        if sets is not None:
            wrong_pass.append(dict(trial=t,outer_guess=guess.tobytes().hex(),
                                   equivalent_candidate_product=str(__import__('math').prod(len(x) for x in sets)),
                                   sizes=[len(x) for x in sets],
                                   equivalent_byte_sets=[x.tolist() for x in sets]))
    row=dict(trial=t,seed=seed,master_key_hex=master.tobytes().hex(),
             genuine_master_key=True,prewhitening_condition='NONE; arbitrary Kpw',
             chosen_plaintexts=512,multisets=2,plaintexts_per_multiset=256,
             distinguisher_two_rounds_passed=True,balanced_bytes=32,
             correct_K4_retained=True,correct_tilde_K3_retained=True,
             K3_to_K2_rotation_passed=True,correct_outer_equivalent_candidate_count=str(size),
             correct_outer_extra_equivalent_candidates=size-1,
             correct_outer_equivalent_byte_sizes=[len(x) for x in G],
             correct_outer_equivalent_byte_sets=[x.tolist() for x in G],
             wrong_full_K4_tested=total,wrong_full_K4_survivors=len(wrong_pass),
             offset_byte4=offset,exhaustive_msb=(t<full_msb_trials))
    if t==0:
        vectors=dict(case='Kalyna-256/512, 2R integral -> 4R Algorithm4',
                     data_per_trial=512,known_answer=test_core(),
                     master_key_hex=master.tobytes().hex(),
                     K0_to_K4=[x.tobytes().hex() for x in k[:5]],
                     true_equivalent_K3=equivalent_true_key(k[3]).tobytes().hex(),
                     candidate_lengths=[len(x) for x in G],
                     sets=[],inverse_ShiftRows_sets=[list(x) for x in I_SETS])
        for (states,c),p in zip(outcomes,ps):
            v=dict(first_plaintext=p[0].tobytes().hex(),
                   second_plaintext=p[1].tobytes().hex(),
                   last_plaintext=p[-1].tobytes().hex(),
                   first_ciphertext=c[0].tobytes().hex(),
                   first_X0=states[0][0].tobytes().hex(),
                   first_X1=states[1][0].tobytes().hex(),
                   first_X2=states[2][0].tobytes().hex(),
                   first_X3=states[3][0].tobytes().hex(),
                   sum_X2=xorsum(states[2]).tobytes().hex(),
                   sum_C=xorsum(c).tobytes().hex())
            vectors['sets'].append(v)
    else:vectors=None
    return row,wrong_pass,vectors


def main():
    p=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument('--trials',type=int,default=1000)
    p.add_argument('--seed',type=int,default=20261117)
    p.add_argument('--jobs',type=int,default=4)
    p.add_argument('--random-wrong',type=int,default=8)
    p.add_argument('--single-bit-wrong',type=int,default=8)
    p.add_argument('--msb-differences',type=int,default=4)
    p.add_argument('--full-msb-trials',type=int,default=2)
    p.add_argument('--progress-every',type=int,default=100)
    p.add_argument('--out',default='KALYNA256_512_R4_RESULTS')
    p.add_argument('--resume',action='store_true')
    args=p.parse_args()
    if args.trials<1 or args.jobs<1 or args.full_msb_trials<0 or args.progress_every<1:
        p.error('Invalid campaign parameters')
    dest=Path(args.out);dest.mkdir(parents=True,exist_ok=True)
    exe=Path(__file__)
    digest=hashlib.sha256(exe.read_bytes()).hexdigest()
    spec=dict(trials=args.trials,seed=args.seed,random_wrong=args.random_wrong,
              single_bit_wrong=args.single_bit_wrong,msb_differences=args.msb_differences,
              full_msb_trials=args.full_msb_trials)
    settings=dest/'settings.json'
    if args.resume:
        if not settings.exists():raise ValueError('No settings.json available for resume')
        previous=json.loads(settings.read_text())
        if previous['configuration']!=spec or previous['source_sha256']!=digest:
            raise ValueError('Resume settings or source hash do not match')
    else:
        if settings.exists() or (dest/'trials.jsonl').exists():
            raise FileExistsError('Output directory already used; choose new --out or --resume')
        settings.write_text(json.dumps(dict(configuration=spec,source_sha256=digest,
                  reference=REFERENCE,reference_commit=REFERENCE_COMMIT,
                  python=sys.version,numpy=np.__version__,platform=platform.platform()),indent=2))
    known=test_core()
    (dest/'official_known_answer.json').write_text(json.dumps(known,indent=2))
    records={}
    if args.resume and (dest/'trials.jsonl').exists():
        for line in (dest/'trials.jsonl').read_text().splitlines():
            if line.strip():
                rec=json.loads(line);records[rec['trial']]=rec
    pending=[i for i in range(args.trials) if i not in records]
    started=time.perf_counter()
    print('Kalyna-256/512: 2R integral + 4R Algorithm4 equivalent-key filtering',flush=True)
    print('Official full cipher KAT PASS; unrestricted genuine 512-bit master keys',flush=True)
    print(f'Full multisets per trial: 2 x 256; trials requested: {args.trials}; remaining: {len(pending)}',flush=True)
    print('All G_i survivors retained (no uniqueness assumption).',flush=True)
    def save(outcome):
        rec,survivors,vectors=outcome
        if rec['trial'] in records:return
        records[rec['trial']]=rec
        with (dest/'trials.jsonl').open('a') as f:f.write(json.dumps(rec,sort_keys=True)+'\n')
        if survivors:
            with (dest/'wrong_outer_survivors.jsonl').open('a') as f:
                for v in survivors:f.write(json.dumps(v,sort_keys=True)+'\n')
        if vectors is not None:
            (dest/'reproducible_test_vectors.json').write_text(json.dumps(vectors,indent=2))
        n=len(records)
        if n%args.progress_every==0 or n==args.trials:
            print(f'Progress {n}/{args.trials}: correct outer {sum(d["correct_K4_retained"] for d in records.values())}/{n}; '
                  f'wrong surviving {sum(d["wrong_full_K4_survivors"] for d in records.values())}; '
                  f'elapsed {time.perf_counter()-started:.1f}s',flush=True)
    if args.jobs==1:
        for t in pending:save(run_trial(t,args.seed,args.random_wrong,args.single_bit_wrong,
                                       args.msb_differences,args.full_msb_trials))
    else:
        with ProcessPoolExecutor(max_workers=args.jobs) as pool:
            futures={pool.submit(run_trial,t,args.seed,args.random_wrong,args.single_bit_wrong,
                                 args.msb_differences,args.full_msb_trials):t for t in pending}
            for ft in as_completed(futures):save(ft.result())
    if len(records)!=args.trials:raise AssertionError('Incomplete 1000-trial campaign')
    rows=[records[i] for i in sorted(records)]
    if not all(r['distinguisher_two_rounds_passed'] and r['correct_K4_retained'] and
               r['correct_tilde_K3_retained'] for r in rows):
        raise AssertionError('Correct candidate or distinguisher failure')
    names=['trial','seed','chosen_plaintexts','distinguisher_two_rounds_passed','balanced_bytes',
           'correct_K4_retained','correct_tilde_K3_retained','correct_outer_equivalent_candidate_count',
           'correct_outer_extra_equivalent_candidates','wrong_full_K4_tested','wrong_full_K4_survivors',
           'offset_byte4','exhaustive_msb']
    with (dest/'trial_summary.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=names);w.writeheader()
        for rec in rows:w.writerow({k:rec[k] for k in names})
    total_extra=sum(x['correct_outer_extra_equivalent_candidates'] for x in rows)
    totals=dict(trials=len(rows),distinguishers_passed=sum(x['distinguisher_two_rounds_passed'] for x in rows),
                valid_multisets=2*len(rows),balanced_bytes_per_multiset=32,
                genuine_512bit_master_keys=len(rows),
                correct_K4_retained=sum(x['correct_K4_retained'] for x in rows),
                correct_equivalent_K3_retained=sum(x['correct_tilde_K3_retained'] for x in rows),
                trials_with_extra_equivalent_candidates=sum(x['correct_outer_extra_equivalent_candidates']>0 for x in rows),
                additional_equivalent_K3_candidates_at_correct_K4=total_extra,
                wrong_full_K4_guesses_tested=sum(x['wrong_full_K4_tested'] for x in rows),
                wrong_full_K4_survivors=sum(x['wrong_full_K4_survivors'] for x in rows),
                nominal_work='2^278 inverse S-box evaluations (NOT encryptions)',
                data_per_trial=512,weak_key_condition='NONE',
                exhaustive_2_pow_256_search_performed=False,
                master_key_recovered=False,
                wall_seconds_current_session=round(time.perf_counter()-started,3))
    (dest/'summary.json').write_text(json.dumps(totals,indent=2))
    report="""# Kalyna-256/512: 2-round integral -> 4-round Algorithm 4

"""
    report+='\n'.join(f'- **{k}**: {v}' for k,v in totals.items())
    report+="""

## Round definition
The distinguisher uses two internal XOR-keyed rounds after standard
columnwise modular pre-whitening. Balance is tested at X2, BEFORE the
terminal modular key addition. The four-round target is:
C = F( F(X2) xor K3 ) boxplus K4.

## Real key schedule and necessary relations
Every trial begins from a random genuine 512-bit master key. K0..K18 are
expanded with the official 256/512 key schedule; K3=RotateLeft_88(K2),
so candidates for K2 are obtained by RotateRight_88(K3).
No restricted/weak key is assumed.

## Algorithm 4 procedure
For each guessed full 256-bit terminal K4, subtract each 64-bit column
modulo 2^64, apply the full F inverse, then L inverse (inverse MC/SR).
For every byte i, keep ALL values g in {0..255} satisfying
XOR_x S_i^{-1}(Y_i(x) xor g)=0 separately on BOTH multisets.
The inverse Sbox input is computed after full-state inverse ShiftRows.
The sets G_i are stored without enforcing |G_i|=1; the total number of
factorized candidates is the product of their cardinalities.
The correct equivalent K3 is L^{-1}(K3), with K3=L(tildeK3).

## Interpretation and limitations
Wrong full K4 guesses are sampled and structured; none of the 2^256
possible terminal subkeys are exhaustively searched. No claim of
complete key recovery, unique round key, or exact full-encryption-equivalent
complexity is made. False-survivor counts are observations of tested keys,
not proofs for all wrong keys. The nominal 2^278 work is an analytical
upper-bound count of inverse S-box evaluations, not a measured runtime.
"""
    (dest/'REPORT.md').write_text(report)
    print('COMPLETE\n'+json.dumps(totals,indent=2),flush=True)
    return 0

if __name__=='__main__':
    raise SystemExit(main())
