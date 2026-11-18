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

def xorsum(x): return np.bitwise_xor.reduce(x,axis=-2)

# ============================================================================
# KALYNA-128/256: 3-ROUND WEAK-PW INTEGRAL + 5-ROUND KEY-CANDIDATE FILTERING
# Self-contained validation: genuine core/KAT; synthetic weak subkeys.
# ============================================================================
from concurrent.futures import ProcessPoolExecutor, as_completed
from collections import Counter

PROGRAM_VERSION = '1.0.0'
ACTIVE = (0,1,2,3,12,13,14,15)
BASE = np.zeros((256,16), dtype=np.uint8)
BASE[:,7] = np.arange(256,dtype=np.uint8)
P3_ZERO = Finv(np.tile(F(np.zeros(16,dtype=np.uint8)),(256,1)) ^ BASE)


def hexbytes(x):
    return np.asarray(x,dtype=np.uint8).tobytes().hex()


def xor_bytes(x):
    return np.bitwise_xor.reduce(x,axis=0)


def assert_equal(a,b,msg):
    if not np.array_equal(a,b):
        raise AssertionError(msg)


def write_json(path,obj):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_suffix(path.suffix+'.tmp')
    temp.write_text(json.dumps(obj,indent=2,sort_keys=True)+'\n')
    os.replace(temp,path)


def trial_seed(root,t):
    return int.from_bytes(hashlib.sha256(f'kalyna128256-r5/{root}/{t}'.encode()).digest()[:8],'little')


def known_answer_tests():
    official=[]
    for n,expected in [(16,'81bf1c7d779bac20e1c9ea39b4d2ad06'),
                       (32,'58ec3e091000158a1148f7166f334f14')]:
        master=np.arange(n,dtype=np.uint8)
        plaintext=np.arange(n,n+16,dtype=np.uint8)
        keys=expand_key(master)
        c=encrypt(plaintext,keys)
        assert hexbytes(c)==expected, 'published encryption known-answer test failed'
        assert_equal(decrypt(c,keys),plaintext,'published round-trip test failed')
        official.append({'variant':f'Kalyna-128/{8*n}',
                         'key':hexbytes(master),'plaintext':hexbytes(plaintext),
                         'ciphertext':expected})
    for n,ct,want in [(16,bytes(range(31,15,-1)),'7291ef2b470cc7846f09c2303973dad7'),
                      (32,bytes(range(47,31,-1)),'f36db456cefddfe1b45b5f7030cad996')]:
        master=np.arange(n-1,-1,-1,dtype=np.uint8)
        assert hexbytes(decrypt(asbytes(ct),expand_key(master)))==want, \
            'published decryption known-answer test failed'
    rng=np.random.default_rng(989)
    batch=rng.integers(0,256,(80,16),dtype=np.uint8)
    assert_equal(Finv(F(batch)),batch,'F inverse failed')
    ka=rng.integers(0,256,(40,16),dtype=np.uint8)
    kb=rng.integers(0,256,(40,16),dtype=np.uint8)
    assert_equal(sub64(add64(ka,kb),kb),ka,'64-bit borrow subtraction failed')
    assert_equal(even_from_odd(odd_from_even(ka)),ka,'odd/even rotation failed')
    assert np.all(P3_ZERO[:,4]==0)
    assert np.all(P3_ZERO[:,[i for i in range(16) if i not in ACTIVE]]==0)
    assert len({bytes(row) for row in P3_ZERO})==256
    assert_equal(F(P3_ZERO),np.tile(F(np.zeros(16,dtype=np.uint8)),(256,1))^BASE,
                 'exact inverse-defined P3 identity failed')
    return {'official_full_cipher_known_answers':official,
            'official_decrypt_test_vectors_passed':2,
            'round_inversions_passed':80,
            'modular_add_sub_inverse_passed':40,
            'inverse_plaintext_formula':'PASS',
            'key_rotation_inverse_passed':40,
            'source_reference_commit':REFERENCE_COMMIT}


def plaintext_multisets(offset):
    """M0={P3(x)}, M1={P3(x) xor (offset*e4)}, with offset in [1,255].
    Byte 4 is a constant position above active 0..3 in column 0.
    Under Kpw[I]=0 it creates no carry into any active byte; its own carry
    and changes in bytes >=4 are independent of the active variable.
    """
    if not 1<=offset<=255:raise ValueError('second-multiset offset must be nonzero')
    a=P3_ZERO.copy();b=P3_ZERO.copy();b[:,4]^=np.uint8(offset)
    assert len({bytes(row) for row in a})==256
    assert len({bytes(row) for row in b})==256
    assert len({bytes(row) for s in (a,b) for row in s})==512
    return (a,b)


def generate_keys(rng):
    """Synthetic Kpw + odd/even-round rotations, NOT expanded from a master key."""
    keys=rng.integers(0,256,(6,16),dtype=np.uint8)
    keys[0,list(ACTIVE)]=0
    for j in (1,3,5):keys[j]=odd_from_even(keys[j-1])
    assert np.all(keys[0,list(ACTIVE)]==0)
    for j in (1,3,5):assert_equal(keys[j],odd_from_even(keys[j-1]),'odd subkey rotation')
    return keys


def bytewise_pattern(states):
    """Conservative bytewise pattern: A -> C -> B -> U precedence."""
    if states.shape != (256,16):raise ValueError('Expected a 256x16 complete multiset')
    xor=xor_bytes(states)
    chars=[]
    for i in range(16):
        f=np.bincount(states[:,i],minlength=256)
        if np.array_equal(f,np.ones(256,dtype=int)):chars.append('A')
        elif np.count_nonzero(f)==1:chars.append('C')
        elif xor[i]==0:chars.append('B')
        else:chars.append('U')
    return ''.join(chars)


def test_distinguisher(p,keys):
    """Full 3R internal states, BEFORE terminal modular addition."""
    x0=add64(p,keys[0]); x1=F(x0)^keys[1]
    x2=F(x1)^keys[2]; x3=F(x2)^keys[3]
    # Exact one-active-byte reduction after first keyed round, even for e4 offset.
    assert np.all((x1^BASE)==(x1^BASE)[0]), 'keyed first-round reduction failed'
    assert np.all(x0[:,list(ACTIVE)]==p[:,list(ACTIVE)]), \
        'pre-whitening modified an active byte'
    # After second round 8 individually A bytes in second column and 8 C.
    assert all(len(np.unique(x2[:,i]))==256 for i in range(8,16)), \
        '2nd-round All column failed'
    assert np.all(x2[:,:8]==x2[0,:8]), '2nd-round constant column failed'
    assert np.all(xor_bytes(x3)==0), '3rd-round 16-byte balancedness failed'
    patterns=[bytewise_pattern(v) for v in (p,x0,x1,x2,x3)]
    expected=('AAAACCCCCCCCAAAA', 'AAAACCCCCCCCAAAA',
              'CCCCCCCACCCCCCCC', 'CCCCCCCCAAAAAAAA', 'BBBBBBBBBBBBBBBB')
    assert tuple(patterns)==expected, f'Unexpected patterns: {patterns}'
    return (x0,x1,x2,x3),patterns


def recover_two_rounds(ciphertexts,outer):
    """Algorithm 3: K4=RotR_56(K5); undo final mod 2^64 addition,
    then F^{-1}, K4 XOR, F^{-1}. Works for a matrix of candidate K5 values.
    """
    g=asbytes(outer).reshape(-1,16)
    k4=even_from_odd(g)
    u=Finv(sub64(ciphertexts[None,:,:],g[:,None,:]))
    return Finv(u^k4[:,None,:])


def candidate_passes(ciphertexts,guesses,batch):
    """Two valid full sets; early reject before second if first fails."""
    if not len(guesses):return []
    result=[]
    for start in range(0,len(guesses),batch):
        chunk=np.stack(guesses[start:start+batch],axis=0)
        recovered0=recover_two_rounds(ciphertexts[0],chunk)
        passed0=np.all(np.bitwise_xor.reduce(recovered0,axis=1)==0,axis=1)
        passed1=np.zeros(len(chunk),dtype=bool)
        if np.any(passed0):
            subchunk=chunk[passed0]
            recovered1=recover_two_rounds(ciphertexts[1],subchunk)
            passed1[passed0]=np.all(np.bitwise_xor.reduce(recovered1,axis=1)==0,axis=1)
        result.extend(zip(passed0.tolist(),passed1.tolist()))
    return result


def incorrect_candidates(rng,k5,random_wrong,msb_count,single_bit,exhaustive_byte):
    """Deduplicated 128-bit incorrect candidates. Oracle-assisted diagnostics only."""
    distinct={}
    genuine=k5.tobytes()
    def add(x,tag):
        h=x.tobytes()
        if h==genuine:return
        distinct.setdefault(h,set()).add(tag)
    if random_wrong:
        for _ in range(random_wrong):add(rng.integers(0,256,16,dtype=np.uint8),'uniform_random')
    if single_bit:
        for bit in range(128):
            x=k5.copy();x[bit//8]^=np.uint8(1<<(bit%8));add(x,'single_bit')
    # Include 0x80 explicitly: addition 2^63 can act as XOR on the MSB bit.
    differences=sorted(set(range(1,msb_count+1))|{0x40,0x80,0xc0,0xff})
    for byte in (7,15):
        for d in differences:
            x=k5.copy();x[byte]^=np.uint8(d);add(x,'most_significant_byte')
    if exhaustive_byte>=0:
        for new in range(256):
            x=k5.copy();x[exhaustive_byte]=new;add(x,f'exhaustive_one_byte_{exhaustive_byte}')
    items=sorted(distinct.items())
    return [np.frombuffer(h,dtype=np.uint8).copy() for h,tags in items],\
           [sorted(tags) for h,tags in items]


def negative_control(p,keys,rng):
    """Attempt invalid Kpw; distinguishers need not fail in every case."""
    other=keys.copy()
    altered=rng.integers(1,256,dtype=np.uint8)
    other[0,0]=altered
    other[1]=odd_from_even(other[0])
    x3=internal(p,other,3,pre=True)
    return bool(np.all(xor_bytes(x3)==0))


def vector_from(p,states,cts,keys,off,subset=(0,1,2,255)):
    return {'offset_e4':int(off),'Kpw':hexbytes(keys[0]),
            'round_keys':{f'K{i}':hexbytes(keys[i]) for i in range(1,6)},
            'selected_points':[
              {'x':int(i),'plaintext':hexbytes(p[i]),
               'after_prewhitening':hexbytes(states[0][i]),
               'X1':hexbytes(states[1][i]),'X2':hexbytes(states[2][i]),
               'X3':hexbytes(states[3][i]),'ciphertext_R5':hexbytes(cts[i])}
              for i in subset],
            'X3_xor_sum':hexbytes(xor_bytes(states[3])),
            'X3_correctly_recovered_xor_sum':hexbytes(xor_bytes(recover_two_rounds(cts,keys[5])[0]))}


def one_trial(t,args):
    outdir=Path(args.out)
    path=outdir/'trials'/f'trial_{t:05d}.json'
    if path.exists():
        obj=json.loads(path.read_text())
        if obj['status']!='PASS':raise RuntimeError('Bad preexisting trial '+str(path))
        return t,True
    rng=np.random.default_rng(trial_seed(args.seed,t))
    keys=generate_keys(rng)
    offset=int(rng.integers(1,256))
    plains=plaintext_multisets(offset)
    stats=[];ciphers=[];vectors=[]
    for j,p in enumerate(plains):
        states,pattern=test_distinguisher(p,keys)
        ciphertext=encrypt(p,keys,5,pre=True)
        ciphers.append(ciphertext)
        stats.append({'multiset':j,'offset_e4':0 if j==0 else offset,
                      'unique_plaintexts':len({bytes(row) for row in p}),
                      'patterns':dict(zip(('P3','after_PW','X1','X2','X3'),pattern)),
                      'X3_xor_sum':hexbytes(xor_bytes(states[3]))})
        # Correct K5 must reconstruct complete X3 exactly, not merely balance.
        got=recover_two_rounds(ciphertext,keys[5])[0]
        assert_equal(got,states[3],'pointwise correct partial-decryption mismatch')
        assert np.all(xor_bytes(got)==0)
        if t==0:vectors.append(vector_from(p,states,ciphertext,keys,0 if j==0 else offset))
    true_results=candidate_passes(ciphers,[keys[5]],args.batch)
    assert true_results==[(True,True)], 'correct final-round key eliminated'
    assert_equal(even_from_odd(keys[5]),keys[4],'K4 recovery from K5 failed')
    # The reference two_round_passes independently gives same 2R inverse test;
    # explicit scalar test on first input verifies candidate path and indexing.
    x=Finv(Finv(sub64(ciphers[0][0],keys[5]))^keys[4])
    assert_equal(x,internal(plains[0][0],keys,3),'scalar inversion mismatch')
    guesses,tags=incorrect_candidates(rng,keys[5],args.random_wrong,args.msb_differences,
                                      args.all_single_bit,args.exhaustive_byte if t<args.exhaustive_byte_trials else -1)
    status=candidate_passes(ciphers,guesses,args.batch)
    assert len(status)==len(guesses)
    wrong_first=sum(x for x,y in status)
    wrong_both=sum(y for x,y in status)
    survivors=[{'K5':hexbytes(g),'K4_derived':hexbytes(even_from_odd(g)),
                'families':tag,'passes_first_multiset':a,'passes_both':b}
               for g,tag,(a,b) in zip(guesses,tags,status) if b]
    negative=negative_control(plains[0],keys,rng) if args.negative_controls else None
    rec={'trial':t,'status':'PASS', 'model':'synthetic_weak_prewhitening_with_odd_even_rotations',
         'master_key':None, 'weak_key_position_set':list(ACTIVE),
         'weak_key_fraction_of_independent_128_bit_subkeys':'2^-64',
         'real_key_schedule_compatibility':'unestablished',
         'round_keys':[hexbytes(k) for k in keys],
         'disjoint_multisets':True,'chosen_plaintexts':512,
         'offset_e4':offset,'distinguisher':stats,
         'correct_key_filter_passes_both':True,
         'correct_K5':hexbytes(keys[5]),
         'correct_K4_derived':hexbytes(even_from_odd(keys[5])),
         'wrong_key_tested_unique':len(guesses),
         'wrong_key_pass_first':wrong_first,
         'wrong_key_pass_both':wrong_both,
         'wrong_key_survivors':survivors,
         'negative_control_balanced':negative}
    write_json(path,rec)
    if t==0:
        write_json(outdir/'reproducible_test_vectors.json',
           {'key_model':rec['model'],'source':'this script, trial 0','reference_commit':REFERENCE_COMMIT,
            'plaintext_multisets':vectors,'full_trial_seed':trial_seed(args.seed,t)})
    return t,False


def final_report(args,kat,elapsed):
    root=Path(args.out)
    trials=[json.loads((root/'trials'/f'trial_{t:05d}.json').read_text()) for t in range(args.trials)]
    assert all(x['status']=='PASS' and x['correct_key_filter_passes_both'] for x in trials)
    count=sum(x['wrong_key_tested_unique'] for x in trials)
    first=sum(x['wrong_key_pass_first'] for x in trials)
    both=sum(x['wrong_key_pass_both'] for x in trials)
    controls=[x['negative_control_balanced'] for x in trials if x['negative_control_balanced'] is not None]
    rows=[]
    for x in trials:
        rows.append({'trial':x['trial'],'input_multisets':2,
           'distinguisher_pass':True,'correct_K5_and_K4_retained':True,
           'wrong_key_tested':x['wrong_key_tested_unique'],
           'wrong_key_survive_first':x['wrong_key_pass_first'],
           'wrong_key_survive_both':x['wrong_key_pass_both'],
           'negative_control_balanced':x['negative_control_balanced']})
    with (root/'trial_summary.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    with (root/'wrong_key_survivors.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=['trial','K5','K4_derived','families','passes_first_multiset','passes_both'])
        w.writeheader()
        for t in trials:
            for s in t['wrong_key_survivors']:
                w.writerow({'trial':t['trial'],**{k:json.dumps(v) if isinstance(v,list) else v for k,v in s.items()}})
    summary={'variant':'Kalyna-128/256','r_dist':3,'R_target':5,
       'method':'Algorithm 3, final 128-bit K5 guess and rotated K4, two round partial inverse',
       'subkey_model':'synthetic weak Kpw; odd/even rotation relations enforced; no master-key expansion',
       'trials':args.trials,'two_disjoint_multisets_per_trial':True,
       'texts_per_multiset':256,'chosen_plaintexts_per_trial':512,
       'underlying_internal_distinguisher_passed':args.trials,
       'correct_K5_retained':args.trials,'correct_K4_rotated_retained':args.trials,
       'incorrect_128bit_K5_guesses_tested_dedup_per_trial':count,
       'incorrect_outer_guesses_surviving_first':first,
       'incorrect_outer_guesses_surviving_both':both,
       'negative_control_violating_restriction_tested':len(controls),
       'negative_control_balanced':sum(controls),'negative_control_unbalanced':len(controls)-sum(controls),
       'nominal_full_space_operation_count':'2^137 full-state two-round partial-decryptions (not full encryptions)',
       'claimed_master_key_recovery':False,
       'wrong_key_test_scope':'sampled/structured oracle-assisted candidates, not 2^128 exhaustive',
       'genuine_master_key_compatible_fraction':'unknown; 2^-64 is a subkey-space fraction only',
       'official_test_vectors':'PASS',
       'source_reference_commit':REFERENCE_COMMIT,
       'wall_seconds':round(elapsed,2)}
    write_json(root/'summary.json',summary)
    report=f"""# Kalyna-128/256: 3-round integral + 5-round candidate filtering

## Stage 1 — exact 3-round internal-state integral

- Complete 256-plaintext multisets: **{args.trials*2} / {args.trials*2} PASS**.
- The two multisets per trial are **disjoint** and share the same restricted key.
- Each uses P3(x)=F^-1(F(0) xor x e7), offset by a fixed nonzero byte at position 4 for the second multiset.
- Active positions: **{ACTIVE}**; Kpw is zero at these eight bytes.
- Exact first-round reduction to one active byte at position 7: PASS.
- After second round: bytes 8..15 are individually All, others Constant.
- After third round: **all 16 bytes XOR-balanced**, before terminal modular addition.

## Stage 2 — two-round partial decryption and filtering (Algorithm 3)

- Target: **5 rounds**, including final column-wise addition mod 2^64.
- K4=RotR(K5) by the prescribed odd-round relation; no independent K4 guess.
- The correct K5 and corresponding K4 are retained in **{args.trials}/{args.trials} trials**.
- Exact recovered X3 equals the forward X3 **pointwise** for all plaintexts.
- **{count:,}** deduplicated incorrect full 128-bit K5 candidates checked.
- Surviving first multiset: **{first:,}**; surviving both: **{both:,}**.
- Violating-key negative controls: **{len(controls)-sum(controls)}/{len(controls)}** unbalanced; this is a sufficient, not necessary, key restriction.

## Reviewer-relevant limitations

- The restricted pre-whitening subkey Kpw is **synthetically generated**; it is not a proven image of the Kalyna-128/256 nonlinear master-key schedule.
- Odd-round subkeys K1,K3,K5 are generated by the correct rotations from K0,K2,K4. This does **not** establish a compatible master key.
- The filter does not exhaust 2^128 outer keys, derive a 256-bit master key, or establish uniqueness over the full outer-key space.
- The work factor 2^137 counts **nominal full-state two-round partial-decryption operations**, excluding key-schedule completion. It is not a number of full encryptions.
- No wrong-key independence or false-positive probability is asserted from the sampled experiments.
- Published encryption/decryption KATs and round inverse identities: PASS.
- Reference code commit: {REFERENCE_COMMIT}.

## Reproduction

Run: `python3 kalyna128_256_5round_combined.py --trials 1000 --jobs 4 --random-wrong 32 --all-single-bit --msb-differences 16 --seed {args.seed} --out RESULT_FOLDER`

Results: `summary.json`, `trial_summary.csv`, `wrong_key_survivors.csv`, `trials/trial_*.json`, `reproducible_test_vectors.json`.
"""
    (root/'REPORT.md').write_text(report)
    return summary


def main():
    p=argparse.ArgumentParser(description='Kalyna-128/256 3R integral -> 5R two-round candidate filtering')
    p.add_argument('--trials',type=int,default=1000)
    p.add_argument('--seed',type=int,default=20261117)
    p.add_argument('--jobs',type=int,default=4)
    p.add_argument('--random-wrong',type=int,default=32)
    p.add_argument('--msb-differences',type=int,default=16,
                   help='Test differences 1..N as well as 0x40,0x80,0xc0,0xff in MSB bytes')
    p.add_argument('--all-single-bit',action=argparse.BooleanOptionalAction,default=True)
    p.add_argument('--negative-controls',action=argparse.BooleanOptionalAction,default=True)
    p.add_argument('--exhaustive-byte',type=int,default=-1,help='-1 none; 0..15 vary full key byte at indicated index')
    p.add_argument('--exhaustive-byte-trials',type=int,default=0)
    p.add_argument('--batch',type=int,default=32)
    p.add_argument('--progress-every',type=int,default=100)
    p.add_argument('--out',type=str,default='KALYNA128_256_R5_RESULTS')
    p.add_argument('--resume',action='store_true')
    args=p.parse_args()
    if args.trials<1 or args.jobs<1 or args.batch<1 or args.progress_every<1 or args.random_wrong<0 or not 0<=args.msb_differences<=255 or not -1<=args.exhaustive_byte<16 or args.exhaustive_byte_trials<0:
        p.error('Invalid numeric argument')
    src_hash=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    scientific={k:v for k,v in vars(args).items() if k not in ('out','jobs','resume','progress_every')}
    scientific.update(script_sha256=src_hash,program_version=PROGRAM_VERSION)
    root=Path(args.out)
    if args.resume:
        cf=root/'config.json'
        if not cf.exists() or json.loads(cf.read_text())!=scientific:
            p.error('--resume needs matching prior config and identical script hash')
    else:
        if root.exists() and any(root.iterdir()):p.error('Output folder nonempty; use --resume or new --out')
        root.mkdir(parents=True,exist_ok=True)
        write_json(root/'config.json',scientific)
    print('Kalyna-128/256 | 3R weak-pre-whitening integral + 5R Algorithm 3 filter',flush=True)
    print('Self-test against published official vectors:',end=' ',flush=True)
    kat=known_answer_tests();print('PASS',flush=True)
    write_json(root/'known_answer_tests.json',kat)
    todo=[t for t in range(args.trials) if not (root/'trials'/f'trial_{t:05d}.json').exists()]
    print(f'Running {len(todo)} pending of {args.trials} trials | jobs={args.jobs} | wrong outer keys sampled',flush=True)
    start=time.monotonic();done=0
    if args.jobs==1:
        for t in todo:
            one_trial(t,args);done+=1
            if done%args.progress_every==0 or done==len(todo):
                print(f'[progress] {done}/{len(todo)} trial jobs complete',flush=True)
    else:
        with ProcessPoolExecutor(max_workers=args.jobs) as pool:
            futures={pool.submit(one_trial,t,args):t for t in todo}
            for future in as_completed(futures):
                future.result();done+=1
                if done%args.progress_every==0 or done==len(todo):
                    print(f'[progress] {done}/{len(todo)} trial jobs complete',flush=True)
    total=round(time.monotonic()-start,2)
    sm=final_report(args,kat,total)
    print('\n=== STAGE 1: 3-ROUND INTEGRAL DISTINGUISHER ===')
    sample=json.loads((root/'trials'/'trial_00000.json').read_text())
    print('Input P3(x):         '+sample['distinguisher'][0]['patterns']['P3'])
    print('After pre-whitening: '+sample['distinguisher'][0]['patterns']['after_PW'])
    for i in (1,2,3):print(f'After round {i}:      '+sample['distinguisher'][0]['patterns'][f'X{i}'])
    print(f'Complete structures: {2*args.trials}/{2*args.trials} PASS; all 16 X3 XOR sums zero')
    print('\n=== STAGE 2: 5-ROUND TWO-ROUND SUBKEY FILTER ===')
    print(f'Correct K5 retained: {sm["correct_K5_retained"]}/{args.trials}')
    print(f'Correct rotated K4 retained: {sm["correct_K4_rotated_retained"]}/{args.trials}')
    print(f'Deduplicated wrong full K5 candidates tested: {sm["incorrect_128bit_K5_guesses_tested_dedup_per_trial"]:,}')
    print(f'Wrong candidates surviving first / both multisets: {sm["incorrect_outer_guesses_surviving_first"]:,} / {sm["incorrect_outer_guesses_surviving_both"]:,}')
    print(f'Negative controls (restriction violated): {sm["negative_control_unbalanced"]}/{sm["negative_control_violating_restriction_tested"]} unbalanced')
    print('Master-key recovery: NOT CLAIMED | exhaustive outer search: NOT DONE')
    print(f'Files: {root}/REPORT.md | summary.json | reproducible_test_vectors.json',flush=True)


if __name__=='__main__':
    main()
