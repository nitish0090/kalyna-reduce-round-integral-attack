#!/usr/bin/env python3
"""Kalyna-128 self-contained validated core, 128/128 and 128/256. Requires NumPy.
Research validation only; not a constant-time cryptographic library.
State bytes are column-major; each group of 8 bytes is a little-endian word.
Constants and schedule checked against the designers' reference implementation:
https://github.com/Roman-Oliynykov/Kalyna-reference
commit 22eafbcaf6635dc5e1f8a734b1f7c5ab84b5a5ea
Reference authors: Ruslan Kiianchuk, Ruslan Mordvinov, Roman Oliynykov.
No network access is used by this script.
"""
import argparse
import csv
import hashlib
import itertools
import json
import math
import os
from pathlib import Path
import platform
import random
import sys
import time
import numpy as np

VERSION = '2.0'
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
I = np.array([0,1,2,3,12,13,14,15])
CASES = {
    'core2': {'r':2,'pre':True,'restriction':'none'},
    'weak3': {'r':3,'pre':True,'restriction':'K0[I]=0'},
    'nopw3': {'r':3,'pre':False,'restriction':'none'},
    'weak4nopw': {'r':4,'pre':False,'restriction':'K1[I]=0'},
}

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


# ===========================================================================
# KALYNA-128/256: 4-ROUND CONDITIONAL INTEGRAL + 6-ROUND FILTERING
# Paper: Section 3.3 -> Section 6 Algorithm 4 (even target R=6).
# MODEL: NO INITIAL PRE-WHITENING. K^(1)[I] = 0, I as below.
# Synthetic independent even subkeys, correct adjacent odd rotations.
# Neither compatibility with a master key nor exhaustive search is claimed.
# ===========================================================================
from concurrent.futures import ProcessPoolExecutor, as_completed
import csv

VERSION_RESEARCH='1.0-combined-reviewed'
R_DIST=4
R_ATTACK=6
N=256
ACTIVE=(0,1,2,3,12,13,14,15)
E7=np.zeros((256,16),dtype=np.uint8)
E7[:,7]=np.arange(256,dtype=np.uint8)
BYTE_VALUES=np.arange(256,dtype=np.uint8)
LOOKUP=np.stack([INV_SBOX[r,BYTE_VALUES[:,None]^BYTE_VALUES[None,:]] for r in range(4)],axis=0)
ZERO=np.zeros(16,dtype=np.uint8)


def check(condition,message):
    if not bool(condition):raise AssertionError(message)


def h(x):return asbytes(x).tobytes().hex()


def xor_sum(x):return np.bitwise_xor.reduce(x,axis=0)


def atomic_json(path,obj):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_name('.'+path.name+'.tmp')
    tmp.write_text(json.dumps(obj,indent=2,sort_keys=True)+'\n',encoding='utf8')
    os.replace(tmp,path)


def rng_for_trial(seed,trial):
    z=hashlib.sha256(f'KALYNA128_256_R6_V1/{seed}/{trial}'.encode()).digest()
    return np.random.default_rng(int.from_bytes(z[:8],'little'))


def pattern(x):
    check(x.shape==(256,16),'Not a full 256x16 multiset')
    sums=xor_sum(x)
    s=[]
    for j in range(16):
        hist=np.bincount(x[:,j],minlength=256)
        s.append('A' if np.all(hist==1) else
                 'C' if np.count_nonzero(hist)==1 else
                 'B' if int(sums[j])==0 else 'U')
    return ''.join(s)


def p3_reference():
    # EXACT 3-round backward structure, before the second backward step.
    return Finv(np.tile(F(ZERO),(256,1))^E7)


def plaintext_structures(offset):
    # P4_a(x) = F^-1( P3(x) xor a e4 ), a in {0,offset}; a!=0.
    # The d=a e4 modification happens INSIDE F^-1, not after it.
    check(1<=offset<=255,'Nonzero offset needed for disjoint multisets')
    base=p3_reference()
    check(np.all(base[:,[i for i in range(16) if i not in ACTIVE]]==0),
          'P3 does not have exact support I')
    out=[]
    for a in (0,offset):
        target=base.copy();target[:,4]^=np.uint8(a)
        p=Finv(target)
        check(np.array_equal(F(p),target),'Incorrect inverse P4 multiset construction')
        check(len({bytes(row) for row in p})==256,'Internal duplicate plaintext')
        out.append(p)
    check(not (set(map(bytes,out[0]))&set(map(bytes,out[1]))),
          'Two inverse-defined chosen-plaintext sets overlap')
    return out


def synthetic_restricted_keys(rng):
    """Prepare K0..K6: K1[I]=0; K1/3/5 obey 56-bit rotations.

    K0 is a bookkeeping even subkey for enforcing K1=RotL(K0).
    The actual reduced cipher omits K0 modular pre-whitening entirely.
    Even K2,K4,K6 are independent synthetic values, not derived from master.
    """
    keys=rng.integers(0,256,(7,16),dtype=np.uint8)
    keys[1,list(ACTIVE)]=0
    keys[0]=even_from_odd(keys[1])
    keys[3]=odd_from_even(keys[2]);keys[5]=odd_from_even(keys[4])
    check(np.all(keys[1,list(ACTIVE)]==0),'Weak K1 condition not enforced')
    for j in (1,3,5):
        check(np.array_equal(keys[j],odd_from_even(keys[j-1])),
              f'Odd subkey K{j} not rotated K{j-1}')
    return keys


def internal_no_prewhitening(p,keys,num_rounds):
    x=p.copy()
    for j in range(1,num_rounds+1):x=F(x)^keys[j]
    return x


def four_round_distinguisher(p,keys,offset):
    """Check exact two-round reduction and marginal byte properties."""
    check(np.all(keys[1,list(ACTIVE)]==0),'K1 weak-key condition absent')
    x1=F(p)^keys[1]
    x2=F(x1)^keys[2]
    x3=F(x2)^keys[3]
    x4=F(x3)^keys[4]
    p3=p3_reference()
    d=np.zeros(16,dtype=np.uint8);d[4]=offset
    expect_x1=p3^d^keys[1]
    check(np.array_equal(x1,expect_x1),'First round did not reduce to exact P3+d+K1')
    # Since support(P3) subset I and support(d+K1) disjoint from I,
    # F(P3+d+K1) = F(P3) + F(d+K1) + F(0).
    constant=F(d^keys[1])^keys[2]
    expect_x2=np.tile(constant,(256,1))^E7
    check(np.array_equal(x2,expect_x2),'Exact second round does not reduce to xe7+C')
    check(np.array_equal(internal_no_prewhitening(p,keys,4),x4),
          'Independent 4R forward mismatch')
    check(np.all(xor_sum(x4)==0),'Four-round distinguisher not balanced on all 16 bytes')
    sig=[pattern(v) for v in (p,x1,x2,x3,x4)]
    check(sig[1]=='AAAACCCCCCCCAAAA',f'X1 expected 8 correlated A, found {sig[1]}')
    check(sig[2]=='CCCCCCCACCCCCCCC',f'X2 expected one A at byte 7, found {sig[2]}')
    check(sig[3]=='CCCCCCCCAAAAAAAA',f'X3 expected 8 A in col1, found {sig[3]}')
    check(sig[4]=='BBBBBBBBBBBBBBBB',f'X4 expected 16 B, found {sig[4]}')
    return (x1,x2,x3,x4),dict(zip(('P4','X1','X2','X3','X4'),sig))


def encrypt_6(p,keys):
    # Actual final layer is modular +K6, not xor. Initial PW is absent.
    return add64(F(internal_no_prewhitening(p,keys,5)),keys[6])


def partial_inverse_two(c,K6,K5):
    # Fully account for 64-bit borrows in C - K6.
    return Finv(Finv(sub64(c,K6))^K5)


def equivalent_trace(c,K6):
    # Y=L^{-1}( F^{-1}(C boxminus K6) ).
    # X4[i]=S_i^{-1}(Y[i] xor g_i), g=L^{-1}(K5).
    return linear_inverse(Finv(sub64(c,K6)))


def equivalent_byte_sets(ylist,early_reject=False):
    """Exhaust all 256 g per byte for the provided 1 or 2 multisets.

    Return (sets, tuple_count). The factored product represents every survivor
    exactly. If early_reject and an empty byte set appears, tuple_count is 0;
    remaining byte sets need not be computed.
    """
    sets=[]
    for i in range(16):
        mask=np.ones(256,dtype=bool)
        for y in ylist:
            hist=np.bincount(y[:,i],minlength=256)&1
            if np.any(hist):
                z=np.bitwise_xor.reduce(LOOKUP[i%4][:,hist.astype(bool)],axis=1)
                mask &= z==0
            if not mask.any():break
        surviving=np.flatnonzero(mask).tolist()
        sets.append(surviving)
        if early_reject and not surviving:return sets,0
    return sets,math.prod(map(len,sets))


def scalar_byte_check(ylist,sets,idxs):
    for i in idxs:
        vset=set(sets[i])
        for g in range(256):
            ok=True
            for y in ylist:
                summ=0
                for value in y[:,i]:summ^=int(INV_SBOX[i%4,int(value)^g])
                if summ:ok=False;break
            check(ok==(g in vset),f'Scalar/vector equivalent-key disagree at i={i}, g={g}')


def negative_control(p,keys,rng):
    # Violate precisely one forbidden K1 byte, keeping K1=RotL(K0) true.
    bad=keys.copy()
    idx=int(rng.choice(np.asarray(ACTIVE)))
    bad[1,idx]=np.uint8(int(rng.integers(1,256)))
    bad[0]=even_from_odd(bad[1])
    check(np.array_equal(bad[1],odd_from_even(bad[0])),'Negative control violates rotation')
    x=internal_no_prewhitening(p,bad,4)
    return {'violated_position':idx,'balanced':bool(np.all(xor_sum(x)==0))}


def validate_known_answers():
    kats=[]
    for n,expect in ((16,'81bf1c7d779bac20e1c9ea39b4d2ad06'),
                     (32,'58ec3e091000158a1148f7166f334f14')):
        master=bytes(range(n));key=expand_key(master)
        p=np.arange(n,n+16,dtype=np.uint8)
        got=encrypt(p,key)
        check(h(got)==expect,'Published KAT encryption failed')
        check(np.array_equal(decrypt(got,key),p),'Published KAT decryption failed')
        kats.append({'master_key_bits':n*8,'master_key_hex':master.hex(),
                    'plaintext_hex':h(p),'ciphertext_hex':expect})
    for n,c,expect in ((16,bytes(range(31,15,-1)),'7291ef2b470cc7846f09c2303973dad7'),
                       (32,bytes(range(47,31,-1)),'f36db456cefddfe1b45b5f7030cad996')):
        key=expand_key(bytes(range(n-1,-1,-1)))
        check(h(decrypt(asbytes(c),key))==expect,'Published KAT decryption failed')
    rng=np.random.default_rng(2026)
    t=rng.integers(0,256,(75,16),dtype=np.uint8)
    k=rng.integers(0,256,(75,16),dtype=np.uint8)
    check(np.array_equal(Finv(F(t)),t),'F inverse test failed')
    check(np.array_equal(sub64(add64(t,k),k),t),'64-bit borrow/carry inverse failed')
    keys=synthetic_restricted_keys(rng)
    p=plaintext_structures(1)[0][:8]
    c=encrypt_6(p,keys)
    check(np.array_equal(partial_inverse_two(c,keys[6],keys[5]),
                         internal_no_prewhitening(p,keys,4)),'Direct terminal two-round inverse failed')
    g=linear_inverse(keys[5]);y=equivalent_trace(c,keys[6])
    check(np.array_equal(partial_inverse_two(c,keys[6],keys[5]),
                         INV_SBOX[np.arange(16)%4,y^g]),'Equivalent byte transform failed')
    check(np.array_equal(linear(g),keys[5]),'Equivalent K5 inverse transform failed')
    check(np.array_equal(even_from_odd(keys[5]),keys[4]),'K5->K4 rotation failed')
    return {'official_encrypt_kats':kats,'official_decrypt_kats_passed':2,
            'round_inverse_random_samples':75,'mod_add_borrow_roundtrips':75,
            'exact_algorithm4_two_round_inverse':'PASS',
            'relevant_restriction':'No initial PW; K1 zero at '+str(ACTIVE)}


def wrong_candidate_families(rng,K6,args,trial):
    """Deduplicated candidates; oracle-assisted near-key tests marked as such."""
    used={h(K6)}; families={}
    def add(fam,guess):
        v=h(guess)
        if v in used:return
        used.add(v);families.setdefault(fam,[]).append(guess.copy())
    for _ in range(args.random_wrong):
        while True:
            x=rng.integers(0,256,16,dtype=np.uint8)
            if h(x) not in used:break
        add('uniform_random_128bit',x)
    bits=range(128) if args.all_single_bit else [(trial*args.single_bit_count+i)%128 for i in range(args.single_bit_count)]
    for b in bits:
        x=K6.copy();x[b//8]^=np.uint8(1<<(b%8))
        add('oracle_assisted_single_bit',x)
    diffs=(range(1,256) if trial<args.full_msb_trials else range(1,args.msb_differences+1))
    for byte in (7,15):
        for delta in diffs:
            x=K6.copy();x[byte]^=np.uint8(delta)
            add('oracle_assisted_msb_column',x)
    if args.exhaustive_byte>=0 and trial<args.exhaustive_byte_trials:
        for val in range(256):
            x=K6.copy();x[args.exhaustive_byte]=np.uint8(val)
            add('oracle_assisted_exhaustive_one_byte',x)
    return families


def vector_data(p,states,ct,keys,a):
    return {'offset_at_P3_byte4':int(a),
      'model':'NO_INITIAL_PREWHITENING_SYNTHETIC_WEAK_K1',
      'restricted_zero_K1_bytes':list(ACTIVE),
      'keys':{f'K{j}':h(keys[j]) for j in range(7)},
      'equivalent_K5':h(linear_inverse(keys[5])),
      'X4_XOR_sums':h(xor_sum(states[3])),
      'selected_points':[{'x':int(x),'P4':h(p[x]),
           'P3_plus_offset':h(F(p[x])),
           'X1':h(states[0][x]),'X2':h(states[1][x]),
           'X3':h(states[2][x]),'X4':h(states[3][x]),
           'C6':h(ct[x])} for x in (0,1,127,255)]}


def one_trial(trial,args):
    root=Path(args.out);path=root/'trials'/f'trial_{trial:05d}.json'
    if path.exists():
        old=json.loads(path.read_text())
        check(old.get('status')=='PASS','Corrupted previous checkpoint')
        return {'trial':trial,'reused':True}
    rng=rng_for_trial(args.seed,trial)
    keys=synthetic_restricted_keys(rng)
    offset=int(rng.integers(1,256))
    pts=plaintext_structures(offset)
    checks=[];ctexts=[];vectors=[]
    for j,(a,p) in enumerate(zip((0,offset),pts)):
        states,sig=four_round_distinguisher(p,keys,a)
        c=encrypt_6(p,keys)
        rec=partial_inverse_two(c,keys[6],keys[5])
        check(np.array_equal(rec,states[3]),'Correct K6/K5 fails pointwise recovery of X4')
        check(np.all(xor_sum(rec)==0),'Correct K6/K5 fails X4 balance')
        checks.append({'multiset':j,'offset_at_P3_byte4':int(a),
                       'patterns':sig,'X4_XOR_sums':h(xor_sum(states[3]))})
        ctexts.append(c)
        if trial<args.vector_trials:vectors.append(vector_data(p,states,c,keys,a))
    outer=keys[6];eq=linear_inverse(keys[5]); ys=[equivalent_trace(c,outer) for c in ctexts]
    eqsets,prod=equivalent_byte_sets(ys,early_reject=False)
    check(prod>=1,'Correct terminal K6 has no equivalent survivor tuples')
    check(all(int(eq[i]) in eqsets[i] for i in range(16)),
          'Correct equivalent K5 byte absent from candidates')
    for c,p in zip(ctexts,pts):
        direct=partial_inverse_two(c,keys[6],keys[5])
        vect=INV_SBOX[np.arange(16)%4,equivalent_trace(c,keys[6])^eq]
        check(np.array_equal(direct,vect),'K5 equivalent-byte formula mismatch')
    if trial==0:scalar_byte_check(ys,eqsets,range(16))
    wrong=wrong_candidate_families(rng,outer,args,trial)
    incorrect=[];famstats={};nfirst=0;nboth=0
    for family,candidates in wrong.items():
        first=0;second=0;tup_first=0;tup_both=0
        for guess in candidates:
            y0=equivalent_trace(ctexts[0],guess)
            g0,n0=equivalent_byte_sets([y0],early_reject=True)
            if n0==0:continue
            first+=1;tup_first+=n0
            y1=equivalent_trace(ctexts[1],guess)
            g1,n1=equivalent_byte_sets([y0,y1],early_reject=True)
            if n1:
                second+=1;tup_both+=n1
                incorrect.append({'family':family,'outer_K6':h(guess),
                        'equivalent_K5_byte_sets':g1,'surviving_equivalent_tuples':n1})
        famstats[family]={'tested':len(candidates),'surviving_first':first,
                          'surviving_both':second,'tuples_first':tup_first,
                          'tuples_both':tup_both}
        nfirst+=first;nboth+=second
    bad=negative_control(pts[0],keys,rng) if args.negative_controls else None
    rec={'trial':trial,'status':'PASS','model':'synthetic weak first internal K1, NO initial pre-whitening',
         'master_key':None,'key_schedule_compatibility':'NOT VERIFIED',
         'subkey_space_cardinality':'2^64 of 2^128 possible K1 values',
         'subkey_fraction_not_master_fraction':'2^-64',
         'restricted_zero_K1_positions':list(ACTIVE),
         'first_round_subkey_K1':h(keys[1]),
         'round_keys':[h(x) for x in keys],
         'pre_whitening_used':False,'odd_rotation_relations_satisfied':True,
         'plaintexts_per_multiset':256,'two_disjoint_multisets':True,
         'distinguisher':checks,'correct_K6':h(keys[6]),
         'correct_K5':h(keys[5]),'derived_K4_from_K5':h(even_from_odd(keys[5])),
         'correct_eq_K5':h(eq),'correct_eq_K5_sets':eqsets,
         'correct_outer_equivalent_tuple_count':int(prod),
         'correct_terminal_and_equivalent_key_retained':True,
         'sampled_wrong_families':famstats,'wrong_candidates_surviving_both':incorrect,
         'negative_control':bad,
         'limitations':['No initial pre-whitening. The reduced model is not standard Kalyna.',
                        'K1 restriction is conditional and synthetic; master-key compatibility unknown.',
                        'Exhaustive outer K6 enumeration and master-key recovery NOT performed.',
                        'G_i survivor sets for each tested K6 are not forced to singleton.']}
    atomic_json(path,rec)
    if trial<args.vector_trials:
        atomic_json(root/'vectors'/f'trial_{trial:05d}.json',
                    {'trial':trial,'seed':args.seed,'p3_offset_byte':4,
                     'P4_formula':'Finv( P3(x) xor a e4 ); P3(x)=Finv(F(0) xor x e7)',
                     'multisets':vectors,
                     'correct_outer_equivalent_K5_sets':eqsets})
    return {'trial':trial,'reused':False,'wrong_tested':sum(v['tested'] for v in famstats.values()),
            'wrong_survive_both':nboth,'true_equivalent_tuples':prod}


def consolidate(args,elapsed,known):
    root=Path(args.out)
    records=[json.loads((root/'trials'/f'trial_{i:05d}.json').read_text()) for i in range(args.trials)]
    check(all(r['status']=='PASS' and r['correct_terminal_and_equivalent_key_retained']
              for r in records),'Not all trials passed')
    allfam={}
    for r in records:
        for fam,vals in r['sampled_wrong_families'].items():
            total=allfam.setdefault(fam,{k:0 for k in vals})
            for k in vals:total[k]+=int(vals[k])
    nwrong=sum(v['tested'] for v in allfam.values())
    nfirst=sum(v['surviving_first'] for v in allfam.values())
    nboth=sum(v['surviving_both'] for v in allfam.values())
    addtuples=sum(r['correct_outer_equivalent_tuple_count']-1 for r in records)
    multisurv=sum(r['correct_outer_equivalent_tuple_count']>1 for r in records)
    controls=[r['negative_control'] for r in records if r['negative_control'] is not None]
    summary={'variant':'Kalyna-128/256','rounds_distinguisher':4,
        'rounds_target':6,'algorithm':'Algorithm 4 even round terminal; K6 guess, equivalent K5 byte filtering',
        'key_model':'SYNTHETIC K1 restricted and no pre-whitening; K1=RotL(K0), K3=RotL(K2), K5=RotL(K4)',
        'full_master_key_expansion_per_trial':False,
        'genuine_master_key_compatibility':'unknown',
        'trials':args.trials,'complete_disjoint_multisets':2*args.trials,
        'plaintexts_per_multiset':256,'chosen_plaintexts_per_trial':512,
        'conditional_distinguisher_passed_trials':args.trials,
        'correct_K6_and_equivalent_K5_retained_trials':args.trials,
        'X4_balanced_bytes':16,
        'zero_positions_K1':list(ACTIVE),'initial_prewhitening':False,
        'admissible_independent_K1_values':'2^64','restricted_K1_subkey_fraction':'2^-64',
        'incorrect_outer_guesses_tested_deduplicated_per_trial':nwrong,
        'incorrect_outer_surviving_first':nfirst,'incorrect_outer_surviving_both':nboth,
        'additional_equivalent_tuples_with_correct_outer':addtuples,
        'trials_with_multiple_equivalent_tuples_correct_outer':multisurv,
        'negative_control_cases':len(controls),
        'negative_control_unbalanced':sum(not r['balanced'] for r in controls),
        'wrong_families':allfam,
        'nominal_work_estimate':'2^149 inverse S-box evaluations (not full encryptions; excluding preprocessing and candidate assembly)',
        'exhaustive_outer_key_search':False,'master_key_recovered':False,
        'reference_commit':REFERENCE_COMMIT,'official_known_answer_tests':'PASS',
        'elapsed_seconds_this_run':round(elapsed,2)}
    atomic_json(root/'summary.json',summary)
    with (root/'trial_summary.csv').open('w',newline='') as f:
        fieldnames=['trial','pass_distinguisher','correct_K6_retained','correct_eq_K5_retained',
          'equivalent_tuples_at_correct_K6','wrong_outer_tested','wrong_outer_first','wrong_outer_both',
          'weak_K1_violating_control_balanced']
        w=csv.DictWriter(f,fieldnames=fieldnames);w.writeheader()
        for r in records:
            fams=r['sampled_wrong_families'];ne=r['negative_control']
            w.writerow(dict(trial=r['trial'],pass_distinguisher=1,
              correct_K6_retained=1,correct_eq_K5_retained=1,
              equivalent_tuples_at_correct_K6=r['correct_outer_equivalent_tuple_count'],
              wrong_outer_tested=sum(a['tested'] for a in fams.values()),
              wrong_outer_first=sum(a['surviving_first'] for a in fams.values()),
              wrong_outer_both=sum(a['surviving_both'] for a in fams.values()),
              weak_K1_violating_control_balanced=ne['balanced'] if ne else 'not tested'))
    with (root/'wrong_key_survivors.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=['trial','family','outer_K6','equivalent_tuple_count','equivalent_K5_sets_json'])
        w.writeheader()
        for r in records:
            for ent in r['wrong_candidates_surviving_both']:
                w.writerow(dict(trial=r['trial'],family=ent['family'],outer_K6=ent['outer_K6'],
                 equivalent_tuple_count=ent['surviving_equivalent_tuples'],
                 equivalent_K5_sets_json=json.dumps(ent['equivalent_K5_byte_sets'])))
    report=[
        '# Kalyna-128/256: 4-round conditional integral + 6-round key-candidate filtering','',
        '## REQUIRED EXACT CONDITIONS','',
        '- Cipher is a **modified reduced-round model without initial modular pre-whitening**.',
        '- First INTERNAL XOR subkey **K^(1)[i] = 0** for i in **'+str(ACTIVE)+'**.',
        '- The other internal subkeys are unrestricted except for the actual adjacent odd/even rotation identities.',
        '- K0 is present only as bookkeeping to satisfy K1 = RotL_56(K0); **K0 is not used to whiten any plaintext**.',
        '- Synthetic subkeys are **not established to arise from a real 256-bit master key**.',
        '- The admissible standalone first-round subkey fraction 2^-64 is **NOT a proven master-key fraction**.','',
        '## Stage 1: full 4-round internal-state distinguisher','',
        f'- Complete independent-key validation trials: **{args.trials}/{args.trials} PASS**.',
        f'- Two distinct full 256-text structures each trial: **{2*args.trials}** checked.',
        '- Define P3(x) = F^-1(F(0) xor x e7) and P4_a(x) = F^-1(P3(x) xor a e4).',
        '- The two structures use a=0 and a nonzero byte; the offset must be inserted before F^-1.',
        '- The first round produces P3(x) xor a e4 xor K1 exactly.',
        '- After two keyed rounds, the state equals constant xor x e7.',
        '- After three rounds, only the second 64-bit column contains eight individually A bytes.',
        '- After four rounds, all 16 internal bytes XOR-balanced (BEFORE terminal addition).','',
        '## Stage 2: 6-round Algorithm 4 filtering','',
        '- Final ciphertext uses +K6 modulo 2^64 **with carries**; inverse uses 64-bit subtraction with borrows.',
        '- Enumerated/sampled full 128-bit K6 outer-key guesses; all 256 equivalent K5 byte guesses tested per relevant position.',
        '- For each tested K6, G_i contains **all** equivalent K5 bytes passing both multisets.',
        '- For correct K6, exact pointwise recovery of X4 agrees with the forward reduced cipher.',
        f'- Correct K6 and equivalent K5 retained: **{args.trials}/{args.trials} trials**.',
        f'- Distinct incorrect outer K6 evaluations (deduplicated per trial): **{nwrong:,}**.',
        f'- Incorrect outer candidates surviving first / both multisets: **{nfirst:,} / {nboth:,}**.',
        f'- Extra equivalent-key tuples for correct K6: **{addtuples:,}**, across **{multisurv}** trials.',
        f'- Violate one zero-byte K1 condition (negative controls): **{summary["negative_control_unbalanced"]}/{len(controls)} unbalanced**.',
        '', '### Incorrect-key diagnostic families',
        '', '| Family | Outer guesses | Survived first | Survived both |','|---|---:|---:|---:|']
    for k,v in sorted(allfam.items()):report.append(f'| {k} | {v["tested"]:,} | {v["surviving_first"]:,} | {v["surviving_both"]:,} |')
    report+=['','## Referee-response limitations','',
       '- This is **conditional round-subkey validation**, not full standard-Kalyna chosen-plaintext master-key recovery.',
       '- The key schedule is checked by official KATs, but the 1,000 conditional trials use synthetic keys.',
       '- Exhaustive 2^128 K6 testing, full master-key verification and global uniqueness are NOT demonstrated.',
       '- Negative controls show failures under sampled nonweak subkeys; conditions are sufficient, not necessary.',
       '- Zero observed wrong-key survivors are not a proof of independence or a false-positive exponent.',
       '- The nominal 2^149 work counts inverse-S-box evaluations; it excludes outer-key preprocessing, tuple assembly and master-key completion.',
       '- Oracle-assisted structured key guesses are diagnostics, not a practical key-guess oracle.','',
       f'- Source pin: designers\' reference commit {REFERENCE_COMMIT}.',
       f'- Scientific run seed: {args.seed}.','',
       'Files: summary.json, trial_summary.csv, wrong_key_survivors.csv, trials/*.json, vectors/*.json.','']
    (root/'REPORT.md').write_text('\n'.join(report))
    return summary


def main():
    ap=argparse.ArgumentParser(description='Kalyna-128/256 NO-PW weak-K1 4-round distinguisher -> 6-round Alg4 filtering')
    ap.add_argument('--trials',type=int,default=1000)
    ap.add_argument('--seed',type=int,default=20261117)
    ap.add_argument('--jobs',type=int,default=4)
    ap.add_argument('--random-wrong',type=int,default=24)
    ap.add_argument('--all-single-bit',action=argparse.BooleanOptionalAction,default=True)
    ap.add_argument('--single-bit-count',type=int,default=16)
    ap.add_argument('--msb-differences',type=int,default=16)
    ap.add_argument('--full-msb-trials',type=int,default=1)
    ap.add_argument('--exhaustive-byte',type=int,default=-1)
    ap.add_argument('--exhaustive-byte-trials',type=int,default=0)
    ap.add_argument('--negative-controls',action=argparse.BooleanOptionalAction,default=True)
    ap.add_argument('--vector-trials',type=int,default=3)
    ap.add_argument('--progress-every',type=int,default=100)
    ap.add_argument('--out',default='KALYNA128_256_R6_RESULTS')
    ap.add_argument('--resume',action='store_true')
    args=ap.parse_args()
    if (args.trials<1 or args.jobs<1 or args.random_wrong<0 or args.single_bit_count<0 or
        not 0<=args.msb_differences<=255 or args.full_msb_trials<0 or args.vector_trials<0 or
        args.exhaustive_byte_trials<0 or not -1<=args.exhaustive_byte<=15 or args.progress_every<1):
        ap.error('Invalid numeric argument')
    root=Path(args.out)
    sh=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    cfg={k:v for k,v in vars(args).items() if k not in ('out','resume','jobs','progress_every')}
    cfg.update(program_sha256=sh,version=VERSION_RESEARCH)
    if args.resume:
        check((root/'config.json').exists(),'Cannot resume without config.json')
        check(json.loads((root/'config.json').read_text())==cfg,'Resume configuration or file hash mismatch')
    else:
        check(not(root.exists() and any(root.iterdir())),'Output folder is nonempty; use --resume or another name')
        root.mkdir(parents=True,exist_ok=True)
        atomic_json(root/'config.json',cfg)
    print('Kalyna-128/256 | 4R NO-PW weak-K1 integral -> 6R Algorithm 4',flush=True)
    print('REQUIRED: no initial PW, K1[0,1,2,3,12,13,14,15]=0; synthetic round subkeys',flush=True)
    print('Official test vectors / inverse / rotated-key selftests:',end=' ',flush=True)
    known=validate_known_answers();print('PASS',flush=True)
    atomic_json(root/'known_answer_tests.json',known)
    atomic_json(root/'environment.json',{'python':sys.version,'numpy':np.__version__,
                                        'platform':platform.platform(),'reference_commit':REFERENCE_COMMIT})
    pending=[i for i in range(args.trials) if not (root/'trials'/f'trial_{i:05d}.json').exists()]
    print(f'Running {len(pending)}/{args.trials} remaining | jobs={args.jobs}',flush=True)
    t0=time.monotonic();complete=0
    if args.jobs==1:
        for i in pending:
            one_trial(i,args);complete+=1
            if complete==1 or complete%args.progress_every==0 or complete==len(pending):
                print(f'[progress] {complete}/{len(pending)}',flush=True)
    else:
        with ProcessPoolExecutor(max_workers=args.jobs) as pool:
            fs={pool.submit(one_trial,i,args):i for i in pending}
            for future in as_completed(fs):
                future.result();complete+=1
                if complete==1 or complete%args.progress_every==0 or complete==len(pending):
                    print(f'[progress] {complete}/{len(pending)}; elapsed {time.monotonic()-t0:.1f}s',flush=True)
    summary=consolidate(args,time.monotonic()-t0,known)
    record=json.loads((root/'trials'/'trial_00000.json').read_text())
    print('\n=== STAGE 1: 4-ROUND CONDITIONAL DISTINGUISHER ===')
    for k,v in record['distinguisher'][0]['patterns'].items():print(f'{k:>4}: {v}')
    print(f'PASS {args.trials}/{args.trials} trials; all 16 X4 byte sums zero',flush=True)
    print('\n=== STAGE 2: 6-ROUND ALGORITHM 4 KEY-CANDIDATE FILTER ===')
    print(f'Correct K6 and equivalent K5 retained: {args.trials}/{args.trials}',flush=True)
    print('Incorrect K6 guessed:',summary['incorrect_outer_guesses_tested_deduplicated_per_trial'],flush=True)
    print('Incorrect K6 surviving first / both:',summary['incorrect_outer_surviving_first'],
          '/',summary['incorrect_outer_surviving_both'],flush=True)
    print('Correct-K6 additional equivalent tuples:',summary['additional_equivalent_tuples_with_correct_outer'],flush=True)
    print('Negative-key controls unbalanced:',summary['negative_control_unbalanced'],
          '/',summary['negative_control_cases'],flush=True)
    print('EXHAUSTIVE K6/MASTER-KEY RECOVERY: NOT DONE | master-key compatibility: UNKNOWN',flush=True)
    print('REPORT:',root/'REPORT.md',flush=True)
    return 0


if __name__=='__main__':raise SystemExit(main())
