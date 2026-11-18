#!/usr/bin/env python3
"""Kalyna-256/256: 2-round integral + 3-round key-column filtering.

Standalone, independently checked against the designers' official
Kalyna-256/256 full-round encryption vector. Research validation only.

State: 4 x 8 bytes, column-major, little-endian 64-bit words.
Round convention: K[0] modular pre-whitening, XOR internal round keys,
K[3] terminal modular addition for the 3-round target. The distinguisher
checks X2 BEFORE terminal addition.

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
from collections import Counter
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
    return dict(official_reference='PASS',ciphertext=expected,key=key.tobytes().hex(),
                plaintext=pt.tobytes().hex(),roundtrip='PASS',state_inversion='PASS',
                terminal_64bit_subtraction='PASS',round_key_rotation='PASS')


def plaintexts(rng):
    """Two independent disjoint 2^8 structures; same random constant base."""
    base=rng.integers(0,256,32,dtype=np.uint8)
    base[7]=0
    a=np.repeat(base[None,:],256,axis=0)
    a[:,7]=np.arange(256,dtype=np.uint8)
    b=a.copy()
    offset=int(rng.integers(1,256))
    b[:,4]^=np.uint8(offset)
    return (a,b),offset


def validate_integral(ps,keys):
    result=[]
    for p in ps:
        if len(np.unique(p[:,7]))!=256: raise AssertionError('Input not All at byte 7')
        if np.any(p[:,np.arange(32)!=7] != p[0,np.arange(32)!=7]):
            raise AssertionError('Nonactive plaintext bytes not constant')
        x0,x1,x2=states_for(p,keys)
        for i in range(32):
            uniq=len(np.unique(x0[:,i]))
            if uniq!=(256 if i==7 else 1): raise AssertionError(('PW invariant',i,uniq))
        # Single active byte moved to column 3 in the first round.
        for i in range(32):
            uniq=len(np.unique(x1[:,i]))
            if uniq!=(256 if 24<=i<32 else 1): raise AssertionError(('Round1 All/C',i,uniq))
        sums=xorsum(x2)
        if np.any(sums): raise AssertionError(('Round2 balancedness failed',sums.tolist()))
        result.append((x0,x1,x2))
    if len(set(map(bytes,[ps[0][0],ps[1][0]]))) != 2: raise AssertionError('Identical structures')
    # Exact disjoint sets (the fixed byte 4 differs).
    if int(ps[0][0,4])==int(ps[1][0,4]): raise AssertionError('Overlapping structures')
    return result


def true_filter_column(cts, j, key_col):
    """Algorithm 1, one 64-bit column; no isolated-column inverse SR."""
    col=np.stack([ct[:,8*j:8*j+8] for ct in cts],axis=0)
    v=mix(sub64(col,key_col),True)
    pre_sr=INV_SBOX[np.arange(8)%4,v]
    sums=np.bitwise_xor.reduce(pre_sr,axis=1)  # 2 x 8
    return bool(np.all(sums==0)),sums


def test_guesses(cts,j,guess_cols,batch=32):
    """Check wrong column guesses in vectorized batches; two-multiset sums."""
    if len(guess_cols)==0:
        return [],0,0
    col=np.stack([ct[:,8*j:8*j+8] for ct in cts],axis=0)
    survivors=[]
    first=0
    count=0
    for s in range(0,len(guess_cols),batch):
        g=a8(guess_cols[s:s+batch])
        # g[G,1,1,8] - col[1,2,256,8] -> [G,2,256,8]
        v=mix(sub64(col[None,:,:,:],g[:,None,None,:]),True)
        t=INV_SBOX[np.arange(8)%4,v]
        sums=np.bitwise_xor.reduce(t,axis=2)   # (G,2,8)
        okfirst=np.all(sums[:,0,:]==0,axis=1)
        okboth=okfirst & np.all(sums[:,1,:]==0,axis=1)
        first+=int(np.count_nonzero(okfirst))
        count+=len(g)
        survivors.extend(g[okboth].tolist())
    return survivors,first,count


def make_wrong_columns(true_col,rng,trial,j,random_wrong,single_bit_wrong,msb_differences,full_msb):
    """Deduplicate within (trial,column), and exclude the correct column."""
    k=np.asarray(true_col,dtype=np.uint8)
    wrong=set()
    def add(candidate):
        value=a8(candidate).tobytes()
        if value!=k.tobytes(): wrong.add(value)
    for _ in range(random_wrong):
        add(rng.integers(0,256,8,dtype=np.uint8))
    for t in range(min(single_bit_wrong,64)):
        q=k.copy()
        bit=(trial*37+j*17+t)%64
        q[bit//8]^=np.uint8(1 << (bit%8))
        add(q)
    if full_msb:
        for d in range(1,256):
            q=k.copy();q[7]^=np.uint8(d);add(q)
    else:
        for t in range(min(msb_differences,255)):
            d=1+((trial*29 + j*41 + t*37)%255)
            q=k.copy();q[7]^=np.uint8(d);add(q)
    # MSB-only +/- 1 and structured modular low-byte perturbations.
    for position in (0,1,6,7):
        for delta in (1,2,128,255):
            q=k.copy();q[position]=np.uint8((int(q[position])+delta)&255);add(q)
    # Numeric carry/borrow-related perturbations.
    val=int.from_bytes(k.tobytes(),'little')
    for d in (1,-1,0x100,-0x100,0x10000,-0x10000,1<<56,-(1<<56),1<<63):
        add(np.frombuffer(((val+d)%(1<<64)).to_bytes(8,'little'),dtype=np.uint8))
    return [np.frombuffer(v,dtype=np.uint8).copy() for v in sorted(wrong)]


def run_trial(trial,seed,random_wrong,single_bit_wrong,msb_differences,full_msb_trials):
    rng=np.random.default_rng(np.random.SeedSequence([int(seed),int(trial),2562563]))
    master=rng.integers(0,256,32,dtype=np.uint8)
    keys=expand_key(master)
    assert np.array_equal(keys[3],odd_from_even(keys[2]))
    ps,offset=plaintexts(rng)
    states=validate_integral(ps,keys)
    cts=[encrypt3(p,keys) for p in ps]
    for c,(_,_,x2) in zip(cts,states):
        reconstructed=Finv(sub64(c,keys[3]))
        if not np.array_equal(reconstructed,x2): raise AssertionError('True 3R pointwise inverse fails')
    true_retained=0;tested=0;wrong_first=0;wrong_both=0
    survivor_rows=[]
    full_msb=trial<full_msb_trials
    for j in range(4):
        keycol=keys[3,8*j:8*j+8]
        passed,sums=true_filter_column(cts,j,keycol)
        if not passed: raise AssertionError(('Correct K3 col eliminated',j,sums.tolist()))
        true_retained+=1
        guesses=make_wrong_columns(keycol,rng,trial,j,random_wrong,single_bit_wrong,msb_differences,full_msb)
        surviving,first,n=test_guesses(cts,j,guesses)
        tested+=n;wrong_first+=first;wrong_both+=len(surviving)
        for v in surviving:
            survivor_rows.append({'trial':trial,'column':j,'candidate':bytes(v).hex(),
                                  'correct':keycol.tobytes().hex()})
    out=dict(trial=trial,seed=seed,chosen_plaintexts=512,master_key_hex=master.tobytes().hex(),
             pw_condition='arbitrary fixed pre-whitening key; NO restrictions',
             distinguisher_two_multisets_passed=True,balanced_bytes_each=32,
             correct_terminal_columns_retained=true_retained,
             wrong_candidate_column_evaluations=tested,
             wrong_pass_first_multiset=wrong_first,wrong_survive_both=wrong_both,
             second_structure_offset_byte4=offset,full_msb_255_per_column=bool(full_msb),
             equivalent_key_rotation_ok=True)
    if trial==0:
        vectors={'first_trial_master_key':master.tobytes().hex(),
                 'round_keys_0_to_3':[k.tobytes().hex() for k in keys[:4]],
                 'I_j':I_SETS,'offset_in_byte4':offset,
                 'two_multisets':[],
                 'known_answer_full_round':verify_primitives()}
        for p,c,(x0,x1,x2) in zip(ps,cts,states):
            vectors['two_multisets'].append(dict(
                first_plaintext=p[0].tobytes().hex(),second_plaintext=p[1].tobytes().hex(),
                last_plaintext=p[-1].tobytes().hex(),
                first_ciphertext=c[0].tobytes().hex(),
                first_prewhitening_state=x0[0].tobytes().hex(),
                first_round1_state=x1[0].tobytes().hex(),
                first_round2_state=x2[0].tobytes().hex(),
                xor_sum_after_round2=xorsum(x2).tobytes().hex(),
                xor_sum_ciphertext=xorsum(c).tobytes().hex()))
    else: vectors=None
    return out,survivor_rows,vectors


def main():
    p=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument('--trials',type=int,default=1000)
    p.add_argument('--seed',type=int,default=20261117)
    p.add_argument('--jobs',type=int,default=1)
    p.add_argument('--random-wrong',type=int,default=16)
    p.add_argument('--single-bit-wrong',type=int,default=16)
    p.add_argument('--msb-differences',type=int,default=16)
    p.add_argument('--full-msb-trials',type=int,default=10)
    p.add_argument('--progress-every',type=int,default=100)
    p.add_argument('--out',default='KALYNA256_256_R3_RESULTS')
    p.add_argument('--resume',action='store_true')
    args=p.parse_args()
    if args.trials<1 or args.jobs<1 or args.full_msb_trials<0:
        p.error('Invalid trials/jobs/full-msb-trials')
    out=Path(args.out);out.mkdir(parents=True,exist_ok=True)
    run_args={'trials':args.trials,'seed':args.seed,'random_wrong':args.random_wrong,
              'single_bit_wrong':args.single_bit_wrong,'msb_differences':args.msb_differences,
              'full_msb_trials':args.full_msb_trials}
    script=Path(__file__)
    hashval=hashlib.sha256(script.read_bytes()).hexdigest()
    settings=out/'settings.json'
    if args.resume and settings.exists():
        saved=json.loads(settings.read_text())
        if saved['args']!=run_args or saved['source_sha256']!=hashval:
            raise ValueError('Resume requires identical experiment settings AND source SHA-256')
    else:
        if (out/'trials.jsonl').exists():
            raise FileExistsError('Output already has trials.jsonl; choose new --out or --resume')
        settings.write_text(json.dumps(dict(args=run_args,source_sha256=hashval,
                      reference=REFERENCE,reference_commit=REFERENCE_COMMIT,
                      python=sys.version,numpy=np.__version__,platform=platform.platform()),indent=2))
    known=verify_primitives()
    (out/'official_known_answer.json').write_text(json.dumps(known,indent=2))
    records={}
    if args.resume and (out/'trials.jsonl').exists():
        for line in (out/'trials.jsonl').read_text().splitlines():
            if line.strip():
                d=json.loads(line);records[d['trial']]=d
    pending=[t for t in range(args.trials) if t not in records]
    started=time.perf_counter()
    print('Kalyna-256/256: key-independent 2R integral + 3R column filtering',flush=True)
    print('Official 256/256 full-cipher KAT: PASS',flush=True)
    print(f'Trials {args.trials}, remaining {len(pending)}, 2 x 256 plaintexts each, 4 columns',flush=True)
    print('Weak-key condition: NONE; K0, K1, K2, K3 from GENUINE master-key schedule',flush=True)
    print(f'I_j: {I_SETS}',flush=True)
    def save_one(result):
        record,survivors,vectors=result
        if record['trial'] in records: return
        records[record['trial']]=record
        with (out/'trials.jsonl').open('a') as f:f.write(json.dumps(record,sort_keys=True)+'\n')
        if survivors:
            with (out/'wrong_key_survivors.jsonl').open('a') as f:
                for r in survivors:f.write(json.dumps(r,sort_keys=True)+'\n')
        if vectors is not None:
            (out/'reproducible_test_vectors.json').write_text(json.dumps(vectors,indent=2))
        count=len(records)
        if count%args.progress_every==0 or count==args.trials:
            print(f'Progress {count}/{args.trials}; correct columns '
                  f'{sum(x["correct_terminal_columns_retained"] for x in records.values())}/{4*count}; '
                  f'wrong surviving {sum(x["wrong_survive_both"] for x in records.values())}; '
                  f'elapsed {time.perf_counter()-started:.1f}s',flush=True)
    if args.jobs==1:
        for t in pending:save_one(run_trial(t,args.seed,args.random_wrong,args.single_bit_wrong,
                                           args.msb_differences,args.full_msb_trials))
    else:
        with ProcessPoolExecutor(max_workers=args.jobs) as exe:
            futures={exe.submit(run_trial,t,args.seed,args.random_wrong,args.single_bit_wrong,
                                args.msb_differences,args.full_msb_trials):t for t in pending}
            for ft in as_completed(futures):save_one(ft.result())
    sorted_records=[records[i] for i in sorted(records)]
    if len(sorted_records)!=args.trials:raise AssertionError('Incomplete campaign')
    if not all(d['distinguisher_two_multisets_passed'] and d['correct_terminal_columns_retained']==4
               for d in sorted_records):raise AssertionError('Integral or true-key failure')
    names=['trial','seed','chosen_plaintexts','distinguisher_two_multisets_passed',
           'balanced_bytes_each','correct_terminal_columns_retained',
           'wrong_candidate_column_evaluations','wrong_pass_first_multiset',
           'wrong_survive_both','second_structure_offset_byte4','full_msb_255_per_column',
           'equivalent_key_rotation_ok']
    with (out/'trial_summary.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=names);w.writeheader()
        for d in sorted_records:w.writerow({key:d[key] for key in names})
    totals={
        'trials':args.trials,'distinguisher_pass':sum(d['distinguisher_two_multisets_passed'] for d in sorted_records),
        'valid_multisets':args.trials*2,'balanced_bytes_per_multiset':32,
        'correct_terminal_columns_retained':sum(d['correct_terminal_columns_retained'] for d in sorted_records),
        'correct_terminal_columns_expected':4*args.trials,
        'wrong_column_candidate_evaluations':sum(d['wrong_candidate_column_evaluations'] for d in sorted_records),
        'wrong_pass_first_multiset':sum(d['wrong_pass_first_multiset'] for d in sorted_records),
        'wrong_survive_both_multisets':sum(d['wrong_survive_both'] for d in sorted_records),
        'full_msb_trials':sum(d['full_msb_255_per_column'] for d in sorted_records),
        'data_per_trial':512,'data_exponent':9,
        'nominal_exhaustive_column_operations':'2^75 (4 columns x 2^64 guesses x 2^9 texts)',
        'nominal_cost_unit':'64-bit column partial decryptions; NOT full encryptions',
        'exhaustive_search_performed':False,'complete_master_key_recovered':False,
        'wrong_survival_claim':'SAMPLED only; none or some survivors are not exhaustive conclusions',
        'elapsed_wall_seconds_current_session':round(time.perf_counter()-started,3)}
    (out/'summary.json').write_text(json.dumps(totals,indent=2))
    report = "# Kalyna-256/256, 2-round distinguisher and 3-round filtering\n\n"
    report += "\n".join(f"- **{k}**: {v}" for k,v in totals.items())
    report += """

## Model and interpretation
Genuine 256-bit master keys, 14-round official Kalyna-256/256 expansion.
Two full 2^8 chosen-plaintext structures per trial, active MSB byte 7, distinct by byte 4.
Pre-whitening key unrestricted. X2 is checked before terminal modular addition.
For the 3-round reduced target, ciphertext C=F(X2) boxplus K^(3).
Algorithm 1 guesses each of the four 64-bit terminal-key columns independently,
undoes modular addition with full borrow propagation, inverts MDS and byte S-boxes,
and tests all eight XOR sums on both multisets. Inverse ShiftRows is accounted for
by the index sets I_j; it is not treated as a single-column operation.
Algorithm 2 only derives K^(2) from a complete surviving K^(3), using
K^(2)=RotateRight_{88 bits}(K^(3)) under this reference byte layout.
The script directly checks that the true K^(3) survives each column filter.
Sampled wrong guesses include random, single-bit, MSB-only and carry-related variants.
This script neither enumerates 2^64 values per column, nor reconstructs a unique
full subkey or master key. Results must not be described as full key recovery.
"""
    (out/'REPORT.md').write_text(report)
    print('COMPLETE',json.dumps(totals,indent=2),flush=True)
    return 0

if __name__=='__main__':
    raise SystemExit(main())
