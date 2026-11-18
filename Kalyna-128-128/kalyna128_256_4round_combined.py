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


# ============================================================================
# Kalyna-128/256: 2-round internal integral + 4-round terminal filtering.
# Section 3.1; Section 6, Algorithm 4, even terminal R=4.
# No weak-key restrictions: every trial uses the GENUINE Kalyna-128/256
# nonlinear master-key schedule and a random 256-bit master key.
# Tested incorrect keys are sampled, NEVER the complete 2^128 outer space.
# ============================================================================
from concurrent.futures import ProcessPoolExecutor, as_completed
import csv
from collections import Counter

VERSION_RESEARCH = '1.0-combined'
R_DIST = 2
R_ATTACK = 4
N = 256
BYTE_VALUES = np.arange(256, dtype=np.uint8)
INVERSE_SBOX_LOOKUP = np.stack([
    INV_SBOX[r, BYTE_VALUES[:,None] ^ BYTE_VALUES[None,:]]
    for r in range(4)
], axis=0)


def require(condition, message):
    if not bool(condition):
        raise AssertionError(message)


def h(x):
    return asbytes(x).tobytes().hex()


def stable_rng(seed, trial):
    raw=hashlib.sha256(f'kalyna128_256_4round/{seed}/{trial}'.encode()).digest()
    return np.random.default_rng(int.from_bytes(raw[:8],'little'))


def atomic_json(path, obj):
    path=Path(path)
    path.parent.mkdir(parents=True,exist_ok=True)
    t=path.with_suffix(path.suffix+'.tmp')
    t.write_text(json.dumps(obj,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    os.replace(t,path)


def xor_sum(states):
    return np.bitwise_xor.reduce(states, axis=0)


def properties(states):
    require(states.shape==(256,16), f'Wrong input shape {states.shape}')
    ans=[]
    for i in range(16):
        counts=np.bincount(states[:,i],minlength=256)
        if np.all(counts==1): ans.append('A')
        elif np.count_nonzero(counts)==1: ans.append('C')
        elif int(xor_sum(states)[i])==0: ans.append('B')
        else: ans.append('U')
    return ''.join(ans)


def two_structures(rng):
    base=rng.integers(0,256,16,dtype=np.uint8)
    base[7]=0
    ret=[]
    for j in (0,1):
        q=base.copy()
        q[4]=np.uint8((int(base[4])+j)%256)
        p=np.tile(q,(256,1))
        p[:,7]=np.arange(256,dtype=np.uint8)
        ret.append(p)
    require(len({p.tobytes() for p in ret})==2,'Equal multisets')
    for p in ret:
        require(len({row.tobytes() for row in p})==256,'Repeated plaintext')
    require(not set(map(bytes,ret[0])) & set(map(bytes,ret[1])),'Overlapping multisets')
    return ret


def distinguish(p, keys):
    x0=add64(p, keys[0])
    x1=F(x0)^keys[1]
    x2=F(x1)^keys[2]
    prop=[properties(p),properties(x0),properties(x1),properties(x2)]
    require(prop[0]=='CCCCCCCACCCCCCCC', f'Wrong input pattern: {prop[0]}')
    require(prop[1]=='CCCCCCCACCCCCCCC', f'Pre-whitening pattern: {prop[1]}')
    require(prop[2]=='CCCCCCCCAAAAAAAA', f'Round 1 pattern: {prop[2]}')
    require(np.all(xor_sum(x2)==0),'2-round integral failed')
    require(prop[3]=='BBBBBBBBBBBBBBBB','2-round resulting marginal property')
    return (x0,x1,x2),prop


def internal_forward(p, keys, rounds):
    x=add64(p,keys[0])
    for r in range(1,rounds+1):
        x=F(x)^keys[r]
    return x


def cipher_4(p,keys):
    # Last round uses actual 64-bit modular addition, never XOR.
    return add64(F(internal_forward(p,keys,3)),keys[4])


def last_two_rounds_direct(ciphertexts, K4, K3):
    # Inverse terminal modular key addition includes every byte borrow.
    u=Finv(sub64(ciphertexts,K4))
    return Finv(u^K3)


def equivalent_trace(ciphertexts, K4):
    # Y = (MC o SR)^{-1}(SB^{-1} SR^{-1} MC^{-1}(C - K4))
    # X2[i] = S_i^{-1}(Y[i] xor g_i), g=(MC o SR)^{-1}(K3).
    u=Finv(sub64(ciphertexts,K4))
    return linear_inverse(u)


def equivalent_byte_sets(two_y, short_circuit=False):
    """All 256 equivalent byte guesses tested for each position, both multisets.

    If any G_i is empty, no full equivalent-key tuple can survive.
    The short_circuit option returns an empty result with an exact rejection;
    it does not claim to have exhaustively checked the remaining bytes.
    """
    sets=[]
    for i in range(16):
        mask=np.ones(256,dtype=bool)
        for y in two_y:
            counts=np.bincount(y[:,i],minlength=256)&1
            if np.any(counts):
                xor=np.bitwise_xor.reduce(INVERSE_SBOX_LOOKUP[i%4][:,counts.astype(bool)],axis=1)
                mask &= xor==0
            if not mask.any(): break
        surviving=np.flatnonzero(mask).tolist()
        sets.append(surviving)
        if short_circuit and not surviving:
            return sets,0
    return sets, math.prod(map(len,sets))


def exhaustive_scalar_equivalence(ylist, gsets, indices=(0,1,2,3,7,8,15)):
    """Independent check of every one of 256 guesses at selected positions."""
    for i in indices:
        expected=set(gsets[i])
        for g in range(256):
            good=True
            for y in ylist:
                s=0
                for v in y[:,i]: s^=int(INV_SBOX[i%4, int(v)^g])
                if s!=0: good=False;break
            require(good==(g in expected),f'Lookup/scalar mismatch i={i},g={g}')


def get_wrong_families(rng,K4,args,trial):
    """Nonexhaustive, deduplicated full-128-bit outer-round-key guesses.

    Single-bit and high-byte families are adversarially chosen relative to the
    known correct K4 (oracle-assisted diagnostic), NOT an attacker oracle.
    """
    used={h(K4)}
    families={}
    def add(name, x):
        hs=h(x)
        if hs in used:return
        used.add(hs)
        families.setdefault(name,[]).append(x)
    for _ in range(args.random_wrong):
        while True:
            x=rng.integers(0,256,16,dtype=np.uint8)
            if h(x) not in used:break
        add('uniform_random_128bit',x)
    # On full mode try all 128 one-bit differences for EVERY genuine key.
    # In lean mode rotate through 128 positions, giving coverage over trials.
    bits=(range(128) if args.all_single_bit else [(trial*args.single_bit_count+j)%128 for j in range(args.single_bit_count)])
    for b in bits:
        x=K4.copy();x[b//8]^=np.uint8(1<<(b%8));add('single_bit_full_key',x)
    # Relevant structured wrong outer keys: byte 7/15 is the most significant
    # little-endian byte of the respective 64-bit column.
    diffs=(range(1,256) if trial<args.full_msb_trials else range(1,args.msb_differences+1))
    for pos in (7,15):
        for dv in diffs:
            x=K4.copy();x[pos]^=np.uint8(dv)
            add('msb_column_xor_difference',x)
    if args.exhaustive_byte>=0 and trial==0:
        for value in range(256):
            x=K4.copy();x[args.exhaustive_byte]=np.uint8(value)
            add('exhaustive_one_byte_outer_key',x)
    return families


def validate_known_answers():
    vectors=[]
    for n,want in ((16,'81bf1c7d779bac20e1c9ea39b4d2ad06'),
                   (32,'58ec3e091000158a1148f7166f334f14')):
        master=bytes(range(n))
        keys=expand_key(master)
        pt=np.arange(n,n+16,dtype=np.uint8)
        actual=encrypt(pt,keys)
        require(h(actual)==want, f'Official {n*8}-bit key KAT failed: {h(actual)}')
        require(np.array_equal(decrypt(actual,keys),pt),'Official KAT decryption mismatch')
        vectors.append(dict(key_bits=n*8,plaintext=h(pt),master_key=master.hex(),ciphertext=want))
    for n,ct,want in ((16,bytes(range(31,15,-1)),'7291ef2b470cc7846f09c2303973dad7'),
                       (32,bytes(range(47,31,-1)),'f36db456cefddfe1b45b5f7030cad996')):
        key=bytes(range(n-1,-1,-1))
        require(h(decrypt(asbytes(ct),expand_key(key)))==want, 'Official decryption KAT failed')
    rng=np.random.default_rng(3214)
    states=rng.integers(0,256,(100,16),dtype=np.uint8)
    require(np.array_equal(Finv(F(states)),states),'F inverse failure')
    k=rng.integers(0,256,(100,16),dtype=np.uint8)
    require(np.array_equal(sub64(add64(states,k),k),states),'64bit carry/borrow roundtrip')
    # Verify exact equivalent-byte representation against direct decryption.
    m=rng.integers(0,256,32,dtype=np.uint8)
    ks=expand_key(m)
    p=rng.integers(0,256,(10,16),dtype=np.uint8)
    ct=cipher_4(p,ks)
    eq=linear_inverse(ks[3]);y=equivalent_trace(ct,ks[4])
    direct=last_two_rounds_direct(ct,ks[4],ks[3])
    byeq=INV_SBOX[np.arange(16)%4,y^eq]
    require(np.array_equal(direct,byeq),'Alg4 equivalent transform not equal direct inverse')
    require(np.array_equal(direct,internal_forward(p,ks,2)),'Alg4 incorrect inverse')
    require(np.array_equal(odd_from_even(ks[2]),ks[3]),'Odd subkey rotation mismatch')
    require(np.array_equal(even_from_odd(ks[3]),ks[2]),'Inverse odd subkey rotation mismatch')
    return dict(reference_commit=REFERENCE_COMMIT, known_answer_tests=vectors,
                decryption_kats=2, random_round_inversions=100,
                carry_borrow_tests=100, equivalent_subkey_and_key_rotation='PASS')


def format_vector(p, states, ct, ks, trial, multiset):
    points=(0,1,127,255)
    return {'trial':trial,'multiset':multiset,
       'genuine_master_key':h(ks['_master']),
       'Kpw':h(ks['keys'][0]), 'K2':h(ks['keys'][2]),
       'K3':h(ks['keys'][3]),'K4_terminal':h(ks['keys'][4]),
       'equivalent_K3':h(linear_inverse(ks['keys'][3])),
       'samples':[{'x':int(t),'plaintext':h(p[t]),
                    'after_prewhitening':h(states[0][t]),
                    'X1':h(states[1][t]),'X2':h(states[2][t]),
                    'ciphertext_R4':h(ct[t])} for t in points],
       'X2_xor_sums':h(xor_sum(states[2]))}


def trial_run(trial,args):
    rng=stable_rng(args.seed,trial)
    master=rng.integers(0,256,32,dtype=np.uint8)
    keys=expand_key(master)
    require(keys.shape==(15,16),'Expected 14-round schedule for 128/256')
    require(np.array_equal(odd_from_even(keys[2]),keys[3]),'Actual K3 not rotated K2')
    plain=two_structures(rng)
    dist=[];prop=[];cts=[]
    for p in plain:
        states,sig=distinguish(p,keys)
        dist.append(states);prop.append(sig)
        ct=cipher_4(p,keys)
        require(np.array_equal(decrypt(ct,keys,4),p),'4-round full encryption/decryption failed')
        cts.append(ct)
    # Exact pointwise statement, rather than only checking 16 balance equations.
    true_eq=linear_inverse(keys[3]); true_outer=keys[4]
    trace=[equivalent_trace(ct,true_outer) for ct in cts]
    true_sets,true_tuples=equivalent_byte_sets(trace,short_circuit=False)
    require(true_tuples>=1,'Correct outer key rejected')
    require(all(int(true_eq[i]) in true_sets[i] for i in range(16)),
            'Correct equivalent byte missing from Algorithm 4 survivors')
    for k,ct in enumerate(cts):
        direct=last_two_rounds_direct(ct,keys[4],keys[3])
        byeq=INV_SBOX[np.arange(16)%4,trace[k]^true_eq]
        require(np.array_equal(byeq,direct),'Equivalent vs direct inverse discrepancy')
        require(np.array_equal(direct,dist[k][2]),'Pointwise 2-round recovery discrepancy')
    if trial==0: exhaustive_scalar_equivalence(trace,true_sets,indices=tuple(range(16)))
    families=get_wrong_families(rng,true_outer,args,trial)
    counts={}; entries=[]
    for fam, candidates in families.items():
        passed=0; tuples=0
        for guess in candidates:
            y=[equivalent_trace(ct,guess) for ct in cts]
            eqsets,n=equivalent_byte_sets(y,short_circuit=True)
            if n:
                passed+=1;tuples+=n
                # Explicitly retain every equivalent byte set, never assume uniqueness.
                entries.append({'family':fam,'outer_K4':h(guess),
                                'tuple_count':n,'equivalent_K3_byte_sets':eqsets})
        counts[fam]={'outer_tested':len(candidates),'outer_survived':passed,
                     'equivalent_tuples_survived':tuples}
    # Complete report for the known-correct outer K4, including any other G_i.
    result={'trial':trial,'status':'PASS','master_key_model':'genuine_Kalyna_128_256_expanded',
       'seed':args.seed,'plaintext_multisets':2,'texts_per_multiset':256,
       'distinguisher_rounds':2,'filtering_rounds':4,
       'distinguisher_passed':True,'distinguisher_byte_patterns':prop,
       'distinguisher_all_16_X2_sums_zero':True,
       'correct_outer_K4':h(true_outer),
       'correct_equivalent_K3':h(true_eq),
       'true_K3_rotation_of_K2':True,
       'correct_K4_survived':True,'correct_equivalent_K3_survived':True,
       'correct_outer_equivalent_tuple_count':true_tuples,
       'correct_outer_byte_set_cardinalities':[len(t) for t in true_sets],
       'correct_outer_equivalent_sets':true_sets,
       'wrong_families':counts,'wrong_survivors':entries,
       'limitations':['Correct-candidate retention is not unique key recovery.',
           'Only sampled and oracle-assisted structured incorrect outer K4 guesses are tested.',
           'The output G_i sets are exact for each TESTED outer guess; the 2^128 outer space is not enumerated.',
           'No complete master-key recovery or encryption-equivalent work is claimed.']}
    path=Path(args.out)/'trials'/f'trial_{trial:05d}.json'
    atomic_json(path,result)
    if trial<args.vector_trials:
        bundle={'_master':master,'keys':keys}
        atomic_json(Path(args.out)/'vectors'/f'vectors_{trial:05d}.json',
                    {'experiment':'Kalyna-128/256 2R+4R',
                     'model':'genuine_256bit_master_key',
                     'multisets':[format_vector(p,st,ct,bundle,trial,i)
                                  for i,(p,st,ct) in enumerate(zip(plain,dist,cts))],
                     'true_equivalent_K3_byte_sets':true_sets,
                     'true_equivalent_key_tuples_for_correct_outer':true_tuples,
                     'full_multiset_generation':'Use P(x)=a xor x e7, x=0..255; two constants differ in byte 4.'})
    return {'trial':trial,'wrong':sum(v['outer_tested'] for v in counts.values()),
            'wrong_survived':sum(v['outer_survived'] for v in counts.values()),
            'true_tuples':true_tuples}


def collate(args,selftest,wall):
    root=Path(args.out)
    records=[json.loads((root/'trials'/f'trial_{t:05d}.json').read_text())
             for t in range(args.trials)]
    require(all(x['status']=='PASS' and x['distinguisher_passed'] and
                x['correct_K4_survived'] and x['correct_equivalent_K3_survived'] for x in records),
            'Incomplete/inconsistent trial records')
    families={}
    for rec in records:
        for fam,s in rec['wrong_families'].items():
            f=families.setdefault(fam,{'outer_tested':0,'outer_survived':0,
                                      'equivalent_tuples_survived':0})
            for k in f:f[k]+=int(s[k])
    nwrong=sum(f['outer_tested'] for f in families.values())
    nouter=sum(f['outer_survived'] for f in families.values())
    ntuples=sum(f['equivalent_tuples_survived'] for f in families.values())
    equivalent_extra=sum(int(rec['correct_outer_equivalent_tuple_count'])-1 for rec in records)
    summary={'experiment':'Kalyna-128/256, 2R integral + 4R last-two-round subkey filtering',
      'version':VERSION_RESEARCH,'trials':args.trials,'distinguisher_pass':args.trials,
      'genuine_256_bit_master_keys':args.trials,'plaintext_multisets_per_trial':2,
      'plaintexts_per_multiset':256,'total_plaintexts_per_trial':512,
      'balanced_internal_bytes':16,
      'correct_outer_key_retained_trials':args.trials,
      'correct_equivalent_K3_retained_trials':args.trials,
      'wrong_outer_key_candidates_tested':nwrong,
      'wrong_outer_key_candidates_surviving':nouter,
      'wrong_equivalent_tuples_surviving':ntuples,
      'additional_equivalent_tuples_for_correct_outer':equivalent_extra,
      'correct_outer_with_more_than_one_equivalent_tuple':sum(int(r['correct_outer_equivalent_tuple_count'])>1 for r in records),
      'wrong_families':families,
      'experimental_wall_seconds':round(wall,3),
      'round_key_scope':'Genuine full 256-bit master key schedule for every trial; sampled R4 outer candidates',
      'analytical_work':'2^149 inverse-S-box evaluations for exhaustive 2^128 last-round outer-key guesses; excluding separate preprocessing, assembly, and master-key verification',
      'no_claims':['No exhaustive 2^128 outer-key enumeration.',
                   'No demonstrated unique K4 or K3 recovery.',
                   'No complete 256-bit master-key recovery.',
                   'No empirical validation of independence-based wrong-key false-positive exponents.']}
    atomic_json(root/'summary.json',summary)
    with (root/'trial_summary.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=['trial','dist_pass','true_K4_retained',
           'true_K3_retained','correct_outer_tuple_count','wrong_tested','wrong_survived','wrong_tuples'])
        w.writeheader()
        for r in records:
            w.writerow({'trial':r['trial'],'dist_pass':int(r['distinguisher_passed']),
             'true_K4_retained':int(r['correct_K4_survived']),
             'true_K3_retained':int(r['correct_equivalent_K3_survived']),
             'correct_outer_tuple_count':r['correct_outer_equivalent_tuple_count'],
             'wrong_tested':sum(a['outer_tested'] for a in r['wrong_families'].values()),
             'wrong_survived':sum(a['outer_survived'] for a in r['wrong_families'].values()),
             'wrong_tuples':sum(a['equivalent_tuples_survived'] for a in r['wrong_families'].values())})
    with (root/'wrong_key_survivors.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=['trial','family','outer_K4','equivalent_tuple_count','equivalent_K3_byte_sets_json'])
        w.writeheader()
        for r in records:
            for s in r['wrong_survivors']:
                w.writerow({'trial':r['trial'],'family':s['family'],
                   'outer_K4':s['outer_K4'],'equivalent_tuple_count':s['tuple_count'],
                   'equivalent_K3_byte_sets_json':json.dumps(s['equivalent_K3_byte_sets'])})
    lines=['# Kalyna-128/256: 2-round integral and 4-round filtering','',
     '## Stage 1 — two-round distinguisher (Section 3.1)','',
     f'- Complete full-input multiset trials: **{summary["distinguisher_pass"]}/{args.trials} PASS**.',
     '- Each trial uses two disjoint sets of 256 chosen plaintexts; 512 chosen plaintexts total.',
     '- All 16 bytes of internal X2 have XOR sum zero before any terminal modular addition.',
     '- Genuine Kalyna-128/256 master keys are expanded by the validated nonlinear key schedule.',
     '', '## Stage 2 — four-round key-candidate filtering (Section 6, Algorithm 4)','',
     f'- Correct full 128-bit terminal K4 retained: **{args.trials}/{args.trials}**.',
     f'- Correct transformed/equivalent K3 retained: **{args.trials}/{args.trials}**.',
     f'- Tested incorrect outer K4 keys: **{nwrong:,}** (not full space).',
     f'- Incorrect outer K4 surviving: **{nouter:,}**.',
     f'- Incorrect equivalent-key tuples surviving: **{ntuples:,}**.',
     f'- Additional equivalent-key tuples at correct K4: **{equivalent_extra:,}**.',
     f'- Trials with multiple equivalent tuples at correct K4: **{summary["correct_outer_with_more_than_one_equivalent_tuple"]}**.',
     '', '| Incorrect-key family | Outer guesses tested | Surviving outer keys | Surviving equivalent tuples |',
     '|---|---:|---:|---:|']
    for name,f in sorted(families.items()):
        lines.append(f'| {name} | {f["outer_tested"]:,} | {f["outer_survived"]:,} | {f["equivalent_tuples_survived"]:,} |')
    lines+=['','## Reproducibility and limitations','',
       '- Full master-key schedule and Kalyna official known-answer test vectors: PASS.',
       '- Terminal key subtraction uses little-endian modulo 2^64 with all borrows.',
       '- The correct X2 is reproduced *pointwise* by direct two-round inverse and the equivalent-key formula.',
       '- Every G_i contains all equivalent-byte guesses accepted for the corresponding tested outer K4; no uniqueness imposed.',
       '- Wrong outer keys tested include random full 128-bit candidates, one-bit differences, and MSB-byte structured guesses.',
       '- Oracle-assisted wrong-key differences are diagnostics, not a practical attacker capability.',
       '- No full 2^128 outer-key search, complete master-key recovery, or verified independence-based false-positive exponent is claimed.',
       '- Nominal 2^149 counts inverse-S-box operations; preprocessing and candidate assembly are separately relevant.',
       '',f'- Elapsed wall time for the validation: {wall:.2f} seconds.',
       '- Source pinned to designers\' reference commit '+REFERENCE_COMMIT+'.','']
    (root/'REPORT.md').write_text('\n'.join(lines))
    return summary


def main():
    parser=argparse.ArgumentParser(description='Combined Kalyna-128/256 2R distinguisher + 4R filtering; all genuine master keys')
    parser.add_argument('--trials',type=int,default=1000)
    parser.add_argument('--jobs',type=int,default=4)
    parser.add_argument('--random-wrong',type=int,default=24)
    parser.add_argument('--all-single-bit',action=argparse.BooleanOptionalAction,default=True)
    parser.add_argument('--single-bit-count',type=int,default=16)
    parser.add_argument('--msb-differences',type=int,default=16)
    parser.add_argument('--full-msb-trials',type=int,default=1)
    parser.add_argument('--exhaustive-byte',type=int,default=-1)
    parser.add_argument('--vector-trials',type=int,default=3)
    parser.add_argument('--progress-every',type=int,default=25)
    parser.add_argument('--seed',type=int,default=20261117)
    parser.add_argument('--out',default='KALYNA128_256_R4_RESULTS')
    parser.add_argument('--resume',action='store_true')
    args=parser.parse_args()
    if args.trials<1 or args.jobs<1 or args.random_wrong<0 or args.single_bit_count<0 or not 0<=args.msb_differences<=255 or args.full_msb_trials<0 or not -1<=args.exhaustive_byte<=15 or args.vector_trials<0:
        parser.error('Invalid numeric argument')
    root=Path(args.out)
    print('[KAT] Testing reference encrypt/decrypt, full 256-bit key schedule, inverse linear maps:',flush=True)
    test=validate_known_answers()
    print('      PASS',flush=True)
    sha=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    settings={k:v for k,v in vars(args).items() if k not in ('out','resume','jobs','progress_every')}
    settings.update({'source_sha256':sha,'version':VERSION_RESEARCH})
    if args.resume:
        require((root/'config.json').exists(), 'No run to resume')
        require(json.loads((root/'config.json').read_text())==settings, 'Resume mismatch: script or settings changed')
    else:
        require(not(root.exists() and any(root.iterdir())),'Output directory nonempty; use --resume or different --out')
        root.mkdir(parents=True,exist_ok=True)
        atomic_json(root/'config.json',settings)
        atomic_json(root/'known_answer_tests.json',test)
        atomic_json(root/'environment.json',{'python':sys.version,'numpy':np.__version__,
             'platform':platform.platform(),'reference_commit':REFERENCE_COMMIT})
    todo=[i for i in range(args.trials) if not (root/'trials'/f'trial_{i:05d}.json').exists()]
    print(f'[START] genuine Kalyna-128/256 | 2R distinguisher -> 4R filtering | '
          f'{len(todo)}/{args.trials} pending | jobs={args.jobs} | '
          f'random wrong={args.random_wrong} | all single-bit={args.all_single_bit}',flush=True)
    t0=time.monotonic();done=0;sample=[]
    if args.jobs==1:
        for t in todo:
            stat=trial_run(t,args);done+=1;sample.append(stat)
            if done==1 or done%args.progress_every==0 or done==len(todo):
                print(f'[progress] {done}/{len(todo)} elapsed={time.monotonic()-t0:.1f}s | last trial={t} | wrong-tested={stat["wrong"]} | wrong-survivors={stat["wrong_survived"]} | true tuples={stat["true_tuples"]}',flush=True)
    else:
        with ProcessPoolExecutor(max_workers=args.jobs) as ex:
            fut={ex.submit(trial_run,i,args):i for i in todo}
            for f in as_completed(fut):
                stat=f.result();done+=1;sample.append(stat)
                if done==1 or done%args.progress_every==0 or done==len(todo):
                    print(f'[progress] {done}/{len(todo)} elapsed={time.monotonic()-t0:.1f}s | last trial={stat["trial"]} | wrong-tested={stat["wrong"]} | wrong-survivors={stat["wrong_survived"]} | true tuples={stat["true_tuples"]}',flush=True)
    summary=collate(args,test,time.monotonic()-t0)
    print('[COMPLETE] 2R balanced trials:',summary['distinguisher_pass'],'/',args.trials,flush=True)
    print('[COMPLETE] 4R true K4 and equivalent K3 retained:',summary['correct_outer_key_retained_trials'],'/',args.trials,flush=True)
    print('[COMPLETE] sampled incorrect outer tested:',summary['wrong_outer_key_candidates_tested'],
          'survived:',summary['wrong_outer_key_candidates_surviving'],flush=True)
    print('[OUTPUT]',root/'REPORT.md',flush=True)
    print('[LIMITATION] No exhaustive 2^128 last-round key search or full master-key recovery.',flush=True)
    return 0


if __name__=='__main__':
    raise SystemExit(main())
