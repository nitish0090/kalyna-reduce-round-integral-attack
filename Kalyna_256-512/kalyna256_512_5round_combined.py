#!/usr/bin/env python3
"""Kalyna-256/512: 3-round two-active-byte integral + 5-round Algorithm 3.

No pre-whitening key restriction. Exact inputs are
P(x,y)=a xor x*e6 xor y*e7 (full GF(256)^2 product); two disjoint sets.
Every trial samples an unrestricted genuine 512-bit master key,
expands it with the validated official key schedule, and verifies balance of
all 32 bytes at internal X3 BEFORE modular post-whitening. The 5-round target
has terminal addition modulo 2^64 and an XOR-keyed internal penultimate round.
Algorithm 3 guesses all 256 bits of K5, derives K4=RotR_88(K5), and
performs two true inverse rounds to test XOR sums of X3 on two multisets.
Sampled wrong-key tests are not exhaustive 2^256 search, and retaining the
correct round-key pair is not master-key recovery. Research validation only.
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

VERSION = '2.0-256512-r5-genuine-active67'
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
# Official vectors, genuine encryption and three-round distinguisher
# ============================================================================
TEST_CT = '606990e9e6b7b67a4bd6d893d72268b78e02c83c3cd7e102fd2e74a8fdfe5dd9'
def xorsum(v):return np.bitwise_xor.reduce(a8(v),axis=-2)

DATA_PER_MULTISET = 1 << 16
D = 2 * DATA_PER_MULTISET
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



# =============================================================================
# Section 4.2 (two active bytes) -> Section 6 Algorithm 3, R = 5
# =============================================================================
ACTIVE = (6,7)
N = 1 << 16
X_VALUES = np.repeat(np.arange(256,dtype=np.uint8),256)
Y_VALUES = np.tile(np.arange(256,dtype=np.uint8),256)
ZERO32 = np.zeros(32,dtype=np.uint8)


def full_product_at(state,i,j):
    """Check every byte pair occurs exactly once; not just marginal All."""
    pairs=(state[:,i].astype(np.uint16)*256 + state[:,j].astype(np.uint16))
    return bool(len(pairs)==N and np.all(np.bincount(pairs,minlength=N)==1))


def genuine_keys(rng):
    """Sample one unrestricted 512-bit master and expand without modification."""
    master=rng.integers(0,256,64,dtype=np.uint8)
    return master,expand_key(master)


def plaintext_structures(rng):
    """Two disjoint full GF(256)^2 products, with distinct byte-4 constant."""
    a=rng.integers(0,256,32,dtype=np.uint8)
    a[6]=0;a[7]=0;a[4]=0
    p=np.tile(a,(N,1));p[:,6]=X_VALUES;p[:,7]=Y_VALUES
    offset=int(rng.integers(1,256))
    q=p.copy();q[:,4]=np.uint8(offset)
    return [p,q],offset


def forward_3dist_5target(p,k):
    """Internal states: X0=PW(P), Xj=F(Xj-1) xor Kj, 1<=j<=4.
    Ciphertext C=F(X4) boxplus K5, each 64-bit column little endian.
    """
    x0=add64(p,k[0])
    x1=F(x0)^k[1]
    x2=F(x1)^k[2]
    x3=F(x2)^k[3]
    x4=F(x3)^k[4]
    c=add64(F(x4),k[5])
    return (x0,x1,x2,x3,x4),c


def validate_structure_and_distinguisher(structures,keys,strict=True):
    if not np.array_equal(keys[1],odd_from_even(keys[0])):raise AssertionError('K1 rotation')
    if not np.array_equal(keys[3],odd_from_even(keys[2])):raise AssertionError('K3 rotation')
    if not np.array_equal(keys[5],odd_from_even(keys[4])):raise AssertionError('K5 rotation')
    if structures[0][0,4]==structures[1][0,4]:raise AssertionError('Sets not disjoint')
    result=[]
    for p in structures:
        if p.shape!=(N,32):raise AssertionError('Wrong multiset size')
        if not full_product_at(p,*ACTIVE):raise AssertionError('Input is not full 2-byte product')
        if strict and np.any(p[:,[i for i in range(32) if i not in ACTIVE]]!=p[0,[i for i in range(32) if i not in ACTIVE]]):
            raise AssertionError('Plaintext nonactive bytes not constant')
        states,c=forward_3dist_5target(p,keys)
        x0,x1,x2,x3,x4=states
        if not full_product_at(x0,*ACTIVE):raise AssertionError('PW destroyed full product')
        if strict:
            if np.any(x0[:,[i for i in range(32) if i not in ACTIVE]]!=x0[0,[i for i in range(32) if i not in ACTIVE]]):
                raise AssertionError('PW introduced unexpected active bytes')
            if np.any(x1[:,:24]!=x1[0,:24]):raise AssertionError('First round active outside final column')
            for i in range(24,32):
                for j in range(i+1,32):
                    if not full_product_at(x1,i,j):
                        raise AssertionError(('X1 pairwise uniformity failed',i,j))
            # A at every byte X2: exact value multiplicity, not an informal label.
            for i in range(32):
                if not np.all(np.bincount(x2[:,i],minlength=256)==256):
                    raise AssertionError(('X2 not All',i))
        sums=xorsum(x3)
        if np.any(sums):raise AssertionError(('3-round internal balance failed',sums.tolist()))
        if not np.array_equal(Finv(sub64(c,keys[5])),x4):
            raise AssertionError('5th terminal modular inverse failed pointwise')
        if not np.array_equal(Finv(x4^keys[4]),x3):
            raise AssertionError('4th internal XOR inverse failed pointwise')
        result.append((states,c,sums))
    return result


def two_round_partial_inverse(ct,guess_k5):
    guess_k4=even_from_odd(guess_k5) # EXACT global RotateR_88 relation
    recovered_x4=Finv(sub64(ct,guess_k5))
    return Finv(recovered_x4^guess_k4)


def filter_terminal_guess(ciphertexts,guess_k5,include_debug=False):
    """Algorithm 3: test 32 zero sums on two complete multisets; early abort."""
    sums=[]
    for ct in ciphertexts:
        x3=two_round_partial_inverse(ct,guess_k5)
        v=xorsum(x3)
        sums.append(v)
        if np.any(v):
            return False,len(sums),sums if include_debug else None
    return True,2,sums if include_debug else None


def choose_wrong_k5(known,rng,trial,random_wrong=1,structured=False,full_msb=False):
    """Sample wrong FULL 256-bit terminal guesses; deduplicate per trial."""
    known=known.copy();kb=known.tobytes();answer={}
    def add(q,category):
        q=a8(q);bb=q.tobytes()
        if bb!=kb:answer.setdefault(bb,category)
    for _ in range(random_wrong):
        add(rng.integers(0,256,32,dtype=np.uint8),'uniform-random')
    if structured:
        # structured single-bit mutations spanning the state
        for j in range(4):
            x=known.copy();bit=(trial*31+j*57)%64
            x[j*8+bit//8]^=np.uint8(1<<(bit%8))
            add(x,'single-bit')
            # MSB differences, including modular-XOR high-bit case
            for d in ((1<<7), (1+trial*17+j*11)%255+1):
                x=known.copy();x[j*8+7]^=np.uint8(d)
                add(x,'msb-byte')
            orig=int.from_bytes(known[j*8:j*8+8].tobytes(),'little')
            for d in (1,-1,1<<56,1<<63):
                x=known.copy()
                x[j*8:j*8+8]=np.frombuffer(((orig+d)%(1<<64)).to_bytes(8,'little'),dtype=np.uint8)
                add(x,'modular-carry')
    if full_msb:
        for j in range(4):
            for d in range(1,256):
                x=known.copy();x[j*8+7]^=np.uint8(d)
                add(x,'all-msb-byte-differences')
    return [(np.frombuffer(k,dtype=np.uint8).copy(),name) for k,name in sorted(answer.items())]


def run_trial(trial,seed,random_wrong,structured_wrong_trials,full_msb_trials):
    rng=np.random.default_rng(np.random.SeedSequence([seed,trial,2565125]))
    master,keys=genuine_keys(rng)
    ps,offset=plaintext_structures(rng)
    outcomes=validate_structure_and_distinguisher(ps,keys,strict=True)
    cts=[x[1] for x in outcomes]
    check,number,balances=filter_terminal_guess(cts,keys[5],include_debug=True)
    if not check or number!=2 or any(np.any(b) for b in balances):
        raise AssertionError('Actual K5 rejected')
    if not np.array_equal(even_from_odd(keys[5]),keys[4]):
        raise AssertionError('Correct K4 not derived from K5')
    for (states,ct,_),p in zip(outcomes,ps):
        if not np.array_equal(two_round_partial_inverse(ct,keys[5]),states[3]):
            raise AssertionError('Correct 2-round inverse is not pointwise X3')
    wrong=choose_wrong_k5(keys[5],rng,trial,random_wrong,
                          structured=trial<structured_wrong_trials,
                          full_msb=trial<full_msb_trials)
    wrong_by_type={};wrong_first=0;wrong_both=0;survivors=[]
    for g,kind in wrong:
        yes,tested,_=filter_terminal_guess(cts,g)
        wrong_first+=tested==2
        wrong_both+=yes
        wrong_by_type[kind]=wrong_by_type.get(kind,0)+1
        if yes:survivors.append(dict(trial=trial,guess_k5_hex=g.tobytes().hex(),kind=kind))
    rec=dict(trial=trial,seed=seed,model='genuine_unrestricted_512bit_master',
             master_key_hex=master.tobytes().hex(),master_candidates_examined=1,
             key_restriction='none',
             prewhitening_subkey_fraction='1',no_initial_prewhitening=False,
             plaintexts_per_multiset=N,multisets=2,chosen_plaintexts=2*N,
             distin_3round_passed=True,balanced_bytes=32,
             correct_K5_retained=True,correct_K4_derived=True,
             wrong_full_K5_tested=len(wrong),wrong_pass_first_multiset=wrong_first,
             wrong_survive_both_multisets=wrong_both,
             wrong_by_category=wrong_by_type,offset_byte4=offset,
             exhaustive_msb_guesses_on_trial=trial<full_msb_trials)
    vectors=None
    if trial==0:
        vectors=dict(case='Kalyna-256/512, 3R two active bytes -> 5R Algorithm 3',
                     key_model=rec['model'],key_restriction=rec['key_restriction'],
                     official_test_vector=test_core(),
                     master_key_hex=master.tobytes().hex(),
                     all_first_six_subkeys=[z.tobytes().hex() for z in keys[:6]],
                     K4_from_K5=even_from_odd(keys[5]).tobytes().hex(),
                     two_active_positions=list(ACTIVE),offset_byte4=offset,
                     multisets=[])
        for (states,c,ss),p in zip(outcomes,ps):
            x0,x1,x2,x3,x4=states
            vectors['multisets'].append(dict(
                plaintext_xy_00=p[0].tobytes().hex(),
                plaintext_xy_01=p[1].tobytes().hex(),
                plaintext_xy_10=p[256].tobytes().hex(),
                plaintext_xy_ff=p[-1].tobytes().hex(),
                ciphertext_xy_00=c[0].tobytes().hex(),
                X0_xy_00=x0[0].tobytes().hex(),
                X1_xy_00=x1[0].tobytes().hex(),
                X2_xy_00=x2[0].tobytes().hex(),
                X3_xy_00=x3[0].tobytes().hex(),
                X4_xy_00=x4[0].tobytes().hex(),
                sum_X3=ss.tobytes().hex(),
                sum_ciphertext=xorsum(c).tobytes().hex(),
                partial_inv_X3_00=two_round_partial_inverse(c[:1],keys[5])[0].tobytes().hex()))
    return rec,survivors,vectors


def main():
    p=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument('--trials',type=int,default=1000)
    p.add_argument('--seed',type=int,default=20261117)
    p.add_argument('--jobs',type=int,default=8)
    p.add_argument('--random-wrong',type=int,default=1,
                   help='Wrong full K5 values for every trial')
    p.add_argument('--structured-wrong-trials',type=int,default=20,
                   help='First N trials add single-bit, MSB and modular-carry guesses')
    p.add_argument('--full-msb-trials',type=int,default=0,
                   help='First N trials exhaust all 255 MSB byte deltas per column (costly)')
    p.add_argument('--progress-every',type=int,default=25)
    p.add_argument('--out',default='KALYNA256_512_R5_ACTIVE67_RESULTS')
    p.add_argument('--resume',action='store_true')
    args=p.parse_args()
    if any(getattr(args,n)<0 for n in ('trials','seed','random_wrong','structured_wrong_trials','full_msb_trials')) or args.trials<1 or args.jobs<1 or args.progress_every<1:
        p.error('Invalid trial or experiment parameters')
    dest=Path(args.out)
    dest.mkdir(parents=True,exist_ok=True)
    source_hash=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    spec={x:getattr(args,x) for x in ('trials','seed','random_wrong','structured_wrong_trials','full_msb_trials')}
    cfg=dest/'settings.json'
    if args.resume:
        if not cfg.exists():raise FileNotFoundError('--resume requires existing settings.json')
        old=json.loads(cfg.read_text())
        if old['configuration']!=spec or old['source_sha256']!=source_hash:
            raise ValueError('Resume parameters/source do not match original run')
    else:
        if cfg.exists() or (dest/'trials.jsonl').exists():
            raise FileExistsError('Results already exist: use --resume or a new --out')
        cfg.write_text(json.dumps(dict(configuration=spec,source_sha256=source_hash,
                      version=VERSION,reference=REFERENCE,commit=REFERENCE_COMMIT,
                      python=sys.version,numpy=np.__version__,platform=platform.platform()),indent=2))
    known=test_core()
    # Check all 28 nonzero GF(256) MDS 2x2 minors for the active rows.
    for a in range(8):
        for b in range(a+1,8):
            determinant=gf(int(MDS[a,6]),int(MDS[b,7])) ^ gf(int(MDS[a,7]),int(MDS[b,6]))
            if determinant==0:raise AssertionError(('MDS columns 6,7 minor singular',a,b))
    (dest/'official_known_answer.json').write_text(json.dumps(known,indent=2))
    records={}
    if args.resume and (dest/'trials.jsonl').exists():
        for l in (dest/'trials.jsonl').read_text().splitlines():
            if l.strip():
                rec=json.loads(l);records[rec['trial']]=rec
    pending=[t for t in range(args.trials) if t not in records]
    tic=time.perf_counter()
    print('Kalyna-256/512 3R two-active integral -> 5R Algorithm3',flush=True)
    print(f'Official 256/512 full encryption KAT PASS | model=GENUINE unrestricted 512-bit masters | target={args.trials} trials',flush=True)
    print('Active positions (6, 7); key restriction NONE; subkey fraction 1',flush=True)
    print(f'Data/trial=2 * 2^16=131072, 32 balanced internal bytes; remaining={len(pending)}',flush=True)
    def save(result):
        rec,wrong,vectors=result
        t=rec['trial']
        if t in records:return
        records[t]=rec
        with (dest/'trials.jsonl').open('a') as f:f.write(json.dumps(rec,sort_keys=True)+'\n')
        if wrong:
            with (dest/'wrong_survivors.jsonl').open('a') as f:
                for w in wrong:f.write(json.dumps(w,sort_keys=True)+'\n')
        if vectors is not None:
            (dest/'reproducible_test_vectors.json').write_text(json.dumps(vectors,indent=2))
        n=len(records)
        if n%args.progress_every==0 or n==args.trials:
            print(f'Progress {n}/{args.trials} | valid structures {2*n} | correct K5 {sum(x["correct_K5_retained"] for x in records.values())} | '
                  f'wrong tested {sum(x["wrong_full_K5_tested"] for x in records.values())} | '
                  f'wrong surviving {sum(x["wrong_survive_both_multisets"] for x in records.values())} | '
                  f'elapsed {time.perf_counter()-tic:.1f}s',flush=True)
    if args.jobs==1:
        for t in pending:
            save(run_trial(t,args.seed,args.random_wrong,args.structured_wrong_trials,
                           args.full_msb_trials))
    else:
        with ProcessPoolExecutor(max_workers=args.jobs) as ex:
            futs=[ex.submit(run_trial,t,args.seed,args.random_wrong,args.structured_wrong_trials,
                            args.full_msb_trials) for t in pending]
            for fut in as_completed(futs):save(fut.result())
    if len(records)!=args.trials:raise AssertionError('Incomplete campaign')
    rows=[records[t] for t in sorted(records)]
    if not all(r['distin_3round_passed'] and r['correct_K5_retained'] and r['correct_K4_derived'] for r in rows):
        raise AssertionError('Missing correct key or integral')
    fields=['trial','master_candidates_examined','chosen_plaintexts','distin_3round_passed','balanced_bytes',
            'correct_K5_retained','correct_K4_derived','wrong_full_K5_tested','wrong_pass_first_multiset',
            'wrong_survive_both_multisets','offset_byte4']
    with (dest/'trial_summary.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
        for r in rows:w.writerow({k:r[k] for k in fields})
    aggregate={}
    for r in rows:
        for cat,c in r['wrong_by_category'].items():aggregate[cat]=aggregate.get(cat,0)+c
    totals=dict(trials=len(rows),distinguishers_passed=sum(r['distin_3round_passed'] for r in rows),
                validated_multisets=2*len(rows),balanced_bytes_per_multiset=32,
                genuine_unrestricted_512bit_master_keys=len(rows),
                master_key_candidates_examined=sum(r['master_candidates_examined'] for r in rows),
                correct_K5_retained=sum(r['correct_K5_retained'] for r in rows),
                correct_K4_derived_by_RotR88=sum(r['correct_K4_derived'] for r in rows),
                wrong_full_K5_tested=sum(r['wrong_full_K5_tested'] for r in rows),
                wrong_pass_first_multiset=sum(r['wrong_pass_first_multiset'] for r in rows),
                wrong_survive_both_multisets=sum(r['wrong_survive_both_multisets'] for r in rows),
                wrong_by_category=aggregate,
                data_per_trial=2*N,MDS_2x2_minors_checked=28,X1_joint_pairs_checked_per_multiset=28,underlying_integral='3-round key-independent two active bytes {6,7}',
                active_positions=list(ACTIVE),key_restriction='none',
                nominal_subkey_fraction='1',admissible_subkey_count='2^256',
                master_key_schedule_compatibility='GENUINE EXPANDED KEYS IN ALL TRIALS',
                nominal_work='2^273 full-state two-round partial decryptions (NOT encryptions)',
                exhaustive_2pow256_search=False,complete_master_key_recovered=False,
                SHA256_python_source=source_hash,wall_seconds_current_session=round(time.perf_counter()-tic,3))
    (dest/'summary.json').write_text(json.dumps(totals,indent=2))
    text='# Kalyna-256/512: 3-round two-active-byte integral -> 5-round Algorithm 3\n\n'
    text+='\n'.join(f'- **{k}**: {v}' for k,v in totals.items())
    text+='''

## Scope and model
The 256-bit state is four 64-bit little-endian columns. The 512-bit
master key is sampled without any restriction and expanded using the genuine
key schedule. No expanded subkey bytes are forced to zero or changed.
The admissible pre-whitening-subkey fraction is 1. Modular pre-whitening
is retained; the upper 16-bit word in the first column is fully active.
Its addition with a fixed subkey word and fixed incoming carry preserves
the complete product structure. All other bytes remain constant.

## Chosen plaintexts and internal-state convention
P_l(x,y) = a_l xor x e6 xor y e7, with the 32-byte constants a_l[6]=a_l[7]=0,
and two disjoint sets with distinct byte-4 constants. Each set contains all
256^2 plaintexts. The chosen-plaintext count is 2*65536=131072=2^17.
The 3-round balancedness holds at internal X3=F(X2) xor K3 before the
5th-round terminal modular addition; the XOR of ciphertexts need not vanish.

## Key filtering (Algorithm 3)
For each guessed full 256-bit terminal K5, derive K4 = RotR_88(K5)
using the real global key-schedule rotation. For each 64-bit ciphertext column
subtract the guessed K5 modulo 2^64 with correct borrow; apply F^{-1} to
recover candidate X4, XOR K4, and apply F^{-1} again to recover candidate X3.
The guessed (K5,K4) pair survives iff all 32 XOR sums at X3 vanish on BOTH
complete multisets. Each surviving wrong candidate is retained. The correct
full-state X3 is also verified pointwise for the real key.

## Evidence limits
The test of random/structured incorrect full 256-bit K5 keys is NOT an
exhaustive 2^256 search. The nominal 2^273 work is expressed in full-state
TWO-ROUND PARTIAL-DECRYPTION operations, not full 5-round encryptions.
Round-key candidate retention does NOT mean complete 512-bit master-key
recovery; the full nonlinear schedule has not been inverted.
The estimated wrong-key rejection probability is not asserted as a proof.
'''
    (dest/'REPORT.md').write_text(text)
    print('COMPLETE\n'+json.dumps(totals,indent=2),flush=True)
    return 0

if __name__=='__main__':
    raise SystemExit(main())
