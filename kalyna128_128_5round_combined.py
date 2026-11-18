#!/usr/bin/env python3
"""Kalyna-128/128 4-round weak-internal-key integral and 5-round key filtering.

Single-file research validation for Sections 3.3 and 6, Table 2 and Algorithms 1-2.
Default: 1000 synthetic restricted FIRST INTERNAL subkey configurations, WITHOUT initial pre-whitening.
Each trial tests two disjoint complete 256-text chosen-plaintext multisets.

This tests (i) the exact 4-round double-inverse-defined multiset under weak K1
and (ii) retention of true 5th-round 64-bit terminal subkey columns.
Wrong-column testing is sampled, including all 255 alternatives for the
MSB key byte per tested true column. No 2^64 exhaustive search or master-key recovery.
Synthetic restricted K1 need not be compatible with genuine master-key expansion.

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
# PART II — Conditional 4R no-PW integral + 5R column key filtering
# ================================================================
from concurrent.futures import ProcessPoolExecutor, wait, FIRST_COMPLETED
from itertools import product

VERSION = '1.0'
BYTE_VALUES = np.arange(256, dtype=np.uint8)
MASK64 = (1 << 64) - 1
I = np.array([0, 1, 2, 3, 12, 13, 14, 15], dtype=int)
NOT_I = np.array([j for j in range(16) if j not in I], dtype=int)
FAMILIES = ('uniform_random_64bit', 'single_bit_xor',
            'all_255_MSB_byte_changes', 'carry_and_modular_boundaries')
ZERO = np.zeros(16, dtype=np.uint8)
E7 = np.zeros((256,16),dtype=np.uint8)
E7[:,7] = BYTE_VALUES


def require(predicate, message):
    if not bool(predicate):
        raise AssertionError(message)


def xor_sum(a):
    return np.bitwise_xor.reduce(np.asarray(a,dtype=np.uint8),axis=0)


def properties(a):
    a=np.asarray(a,dtype=np.uint8)
    xx=xor_sum(a)
    out=[]
    for pos in range(16):
        freq=np.bincount(a[:,pos],minlength=256)
        if np.count_nonzero(freq)==1:out.append('C')
        elif a.shape[0]%256==0 and np.all(freq==a.shape[0]//256):out.append('A')
        elif xx[pos]==0:out.append('B')
        else:out.append('U')
    return ''.join(out)


def p3_base():
    """Exact P3=F^-1(F(0) xor x e7), key independent."""
    p3=Finv(np.tile(F(ZERO),(256,1)) ^ E7)
    require(np.all(p3[:,NOT_I]==0), 'P3 variable support invalid')
    require(np.all(p3[0]==0), 'P3(0)!=0')
    require(np.array_equal(F(p3),np.tile(F(ZERO),(256,1)) ^ E7),
            'P3 inverse-round relation invalid')
    for j in I:
        require(np.array_equal(np.sort(p3[:,j]),BYTE_VALUES),
                f'P3 byte {j} not individually All')
    return p3


def two_multisets(rng):
    """P4^a(x)=F^-1(P3(x) xor a*e4), for a=0 or a!=0.

    The first keyed round yields P3(x) xor a*e4 xor K1, for both structures.
    The offset byte 4 is outside I, so disjoint-support translation applies
    if K1 vanishes on I. These are NOT arbitrary translations of P4.
    """
    p3=p3_base()
    offset=int(rng.integers(1,256))
    p3_shift=p3.copy()
    p3_shift[:,4] ^= np.uint8(offset)
    p0=Finv(p3)
    p1=Finv(p3_shift)
    require(np.array_equal(F(p0),p3),'P4 inverse identity for first multiset failed')
    require(np.array_equal(F(p1),p3_shift),'P4 inverse identity for second multiset failed')
    require(np.unique(np.concatenate((p0,p1),axis=0),axis=0).shape[0]==512,
            'The two inverse-defined multisets must be disjoint and internally distinct')
    return (p0,p1), offset


def synthetic_keys(rng):
    """Synthetic K1[I]=0 and real odd-even rotation relations.

    K0 is the even-indexed predecessor of K1, but is NOT applied as
    pre-whitening. K1, K3 and K5 use Kalyna's odd-subkey rotation.
    The nonlinear master-key schedule is NOT asserted satisfied.
    """
    keys=rng.integers(0,256,(6,16),dtype=np.uint8)
    keys[1,I]=0
    keys[0]=even_from_odd(keys[1])
    keys[3]=odd_from_even(keys[2])
    keys[5]=odd_from_even(keys[4])
    require(np.all(keys[1,I]==0),'weak internal K1 condition not enforced')
    for odd in (1,3,5):
        require(np.array_equal(keys[odd],odd_from_even(keys[odd-1])),
                f'key relation K{odd}=Rot(K{odd-1}) invalid')
    return keys


def states_and_distinguisher(p,keys,offset):
    """Check the exact link at round 2 before A/C/B integral properties."""
    x0=p.copy()  # IMPORTANT: no initial pre-whitening
    x1=F(x0)^keys[1]
    x2=F(x1)^keys[2]
    x3=F(x2)^keys[3]
    x4=F(x3)^keys[4]
    p3=p3_base()
    translated=p3.copy()
    translated[:,4]^=np.uint8(offset)
    require(np.array_equal(F(p),translated),'incorrect exact P4-to-P3 inverse')
    require(np.array_equal(x1,translated ^ keys[1]),'incorrect first keyed round')
    require(np.all(x1[:,I]==p3[:,I]),'weak K1 changed dependent active byte positions')
    require(np.all(x1[:,NOT_I]==x1[0,NOT_I]),'X1 outside I not constant')
    # The theorem depends on the exact correlated P3 structure, not the A symbols.
    require(np.all((x2 ^ E7)==(x2^E7)[0]),
            'Round 2 did not recover exact translated one-active-byte family')
    require(np.array_equal(np.sort(x2[:,7]),BYTE_VALUES),'X2 byte7 not All')
    require(np.all(x2[:,np.arange(16)!=7]==x2[0,np.arange(16)!=7]),
            'X2 other 15 bytes not constant')
    require(np.all(x3[:,:8] == x3[0,:8]), 'X3 first column not constant')
    for j in range(8,16):
        require(np.array_equal(np.sort(x3[:,j]),BYTE_VALUES),
                f'X3 byte {j} not All')
    ss=xor_sum(x4)
    require(np.all(ss==0),'X4 not balanced: '+ss.tobytes().hex())
    return (x0,x1,x2,x3,x4),{
        'input':properties(x0),'round1':properties(x1),'round2':properties(x2),
        'round3':properties(x3),'round4':properties(x4),
        'round4_zero_xor_bytes':int(np.count_nonzero(ss==0)),
        'round4_xor_sum_hex':ss.tobytes().hex(),
        'exact_inverse_P4_identity':True,
        'exact_second_round_one_variable_translation':True,
        'plaintext_sha256':hashlib.sha256(p.tobytes()).hexdigest(),
        'X4_sha256':hashlib.sha256(x4.tobytes()).hexdigest(),
        'inner_P3_offset_byte4':offset,
    }

def col_inversion_sums(ct_col, guesses):
    """Terminal modular subtraction (with borrows), inv MC, inv SB, byte sums.

    Returned 8 bytes are ordered by output row; they refer to source I_j under
    the inverse ShiftRows. Do not shift a single 64-bit column in isolation.
    """
    guess_array = np.asarray(guesses,dtype=np.uint8).reshape(-1,8)
    if len(guess_array)==0:
        return np.empty((0,8),dtype=np.uint8)
    z = sub64(ct_col[None,:,:], guess_array[:,None,:])
    v = mix(z,inverse=True)
    return np.bitwise_xor.reduce(INV_SBOX[np.arange(8)%4, v],axis=1)


def key_col(full,col):
    return np.asarray(full[8*col:8*col+8],dtype=np.uint8)


def check_true_column(cts,truekey,col,expected_x3s):
    candidate = key_col(truekey,col)
    positions = SR[8*col:8*col+8]
    for j,ct in enumerate(cts):
        ss=col_inversion_sums(ct[:,8*col:8*col+8],candidate[None,:])
        require(np.all(ss==0), 'true terminal key column must survive')
        full=Finv(sub64(ct,truekey))
        require(np.array_equal(full,expected_x3s[j]), 'full inverse did not recover X3')
        z=sub64(ct[:,8*col:8*col+8],candidate)
        via_col=INV_SBOX[np.arange(8)%4,mix(z,inverse=True)]
        require(np.array_equal(via_col,full[:,positions]),'column/full inv mismatch')
    return [int(k) for k in positions]


def key_from_int(v):
    return (v&MASK64).to_bytes(8,'little')


def wrong_families(truekey,rng,count,full_msb):
    correct=bytes(truekey)
    v=int.from_bytes(correct,'little')
    randoms=set()
    while len(randoms)<count:
        value=bytes(rng.integers(0,256,8,dtype=np.uint8))
        if value != correct: randoms.add(value)
    singles={key_from_int(v^(1<<i)) for i in range(64)}
    msbs={correct[:7]+bytes([z]) for z in range(256) if z!=correct[7]} if full_msb else set()
    boundaries={key_from_int(z) for z in (
        0,MASK64,v+1,v-1,v+(1<<63),v-(1<<63),v^(1<<63),
        v+(1<<56),v-(1<<56),v+0xff,v-0xff,v^0xff,v^0xff00,
        v^0xffff,v^0xffffffff,v^(MASK64>>1),
    )}
    out=dict(zip(FAMILIES,(randoms,singles,msbs,boundaries)))
    for s in out.values():s.discard(correct)
    return out


def test_wrong_columns(cts,col,families,chunk_size):
    union=sorted(set().union(*families.values()))
    pass1=set();pass2=set()
    for offset in range(0,len(union),chunk_size):
        choices=union[offset:offset+chunk_size]
        guesses=np.frombuffer(b''.join(choices),dtype=np.uint8).reshape(-1,8)
        ss=col_inversion_sums(cts[0][:,8*col:8*col+8],guesses)
        survived=[choices[int(i)] for i in np.flatnonzero(np.all(ss==0,axis=1))]
        pass1.update(survived)
        if survived:
            guesses2=np.frombuffer(b''.join(survived),dtype=np.uint8).reshape(-1,8)
            yy=col_inversion_sums(cts[1][:,8*col:8*col+8],guesses2)
            pass2.update(k for k,ok in zip(survived,np.all(yy==0,axis=1)) if ok)
    detail={}
    for name in FAMILIES:
        q=families[name]
        detail[name]={
            'tested':len(q), 'survive_first_multiset':len(q&pass1),
            'survive_both_multisets':len(q&pass2),
            'survivors_hex':[v.hex() for v in sorted(q&pass2)],
        }
    return detail,{
       'unique_wrong_candidates_tested':len(union),
       'unique_wrong_surviving_first_multiset':len(pass1),
       'unique_wrong_surviving_both_multisets':len(pass2),
       'all_unique_wrong_survivor_hex':[v.hex() for v in sorted(pass2)],
       'union_sha256':hashlib.sha256(b''.join(union)).hexdigest(),
    }




def trial_rng(seed,number):
    h=hashlib.sha256(f'kalyna128_128_R5_noPW_weakK1|{seed}|{number}'.encode()).digest()
    return np.random.default_rng(int.from_bytes(h[:16],'little'))


def samples(p,states,ct):
    x0,x1,x2,x3,x4=states
    return [dict(x=x,plaintext=p[x].tobytes().hex(),
         after_round1=x1[x].tobytes().hex(), after_round2=x2[x].tobytes().hex(),
         after_round3=x3[x].tobytes().hex(), after_round4=x4[x].tobytes().hex(),
         ciphertext_5round=ct[x].tobytes().hex()) for x in (0,1,128,255)]


def one_trial(tidx,cfg):
    rng=trial_rng(cfg['seed'],tidx)
    keys=synthetic_keys(rng)
    ps,offset=two_multisets(rng)
    ctsets=[];states=[];details=[]
    for i,p in enumerate(ps):
        st,dist=states_and_distinguisher(p,keys,0 if i==0 else offset)
        ct=add64(F(st[-1]),keys[5])
        require(np.array_equal(ct,encrypt(p,keys,rounds=5,pre=False)),
                '5R ciphertext mismatch with independent encrypt(pre=False)')
        dist['multiset']=i
        dist['ciphertext_sha256']=hashlib.sha256(ct.tobytes()).hexdigest()
        dist['terminal_ciphertext_xor_sum_hex']=xor_sum(ct).tobytes().hex()
        ctsets.append(ct);states.append(st);details.append(dist)
    # Violating K1 negative controls are NOT a proof of necessity.
    negative_keys=keys.copy()
    negative_keys[1]=rng.integers(0,256,16,dtype=np.uint8)
    negative_keys[1,0]=np.uint8(1)
    negative_keys[0]=even_from_odd(negative_keys[1])
    negative_balances=[int(np.count_nonzero(xor_sum(internal(pp,negative_keys,4,pre=False))==0))
                       for pp in ps]
    cols=[];column_sets=[]
    for col in (0,1):
        positions=check_true_column(ctsets,keys[5],col,[s[-1] for s in states])
        true=key_col(keys[5],col)
        wrong=wrong_families(true,rng,cfg['random_wrong'],cfg['full_msb'])
        breakdown,unique=test_wrong_columns(ctsets,col,wrong,cfg['chunk_size'])
        cols.append({'column':col,'index_set_Ij':positions,
           'true_terminal_64bit_key_hex':true.tobytes().hex(),
           'true_candidate_retained_by_both_multisets':True,
           'wrong_candidate_families':breakdown,
           'deduplicated_wrong_testing':unique})
        column_sets.append(sorted({bytes(true)} |
            {bytes.fromhex(h) for h in unique['all_unique_wrong_survivor_hex']}))
    count=len(column_sets[0])*len(column_sets[1])
    tuples=[]
    if count<=512:
        for aa,bb in product(*column_sets):
            full=np.frombuffer(aa+bb,dtype=np.uint8).copy()
            predecessor=even_from_odd(full)
            tuples.append({'K5_hex':full.tobytes().hex(),
                           'K4_derived_hex':predecessor.tobytes().hex(),
                           'is_true_K5':bool(np.array_equal(full,keys[5])),
                           'is_true_K4':bool(np.array_equal(predecessor,keys[4]))})
        require(any(z['is_true_K5'] and z['is_true_K4'] for z in tuples),
                'True K5/K4 candidate pair was omitted')
    record={
      'trial':tidx,'status':'PASS','variant':'Kalyna-128/128',
      'key_model':'synthetic weak FIRST INTERNAL K1, WITHOUT initial pre-whitening; no genuine master-key expansion claimed',
      'master_key_hex':None,
      'keys_K0_unapplied_K1_K2_K3_K4_K5_hex':[k.tobytes().hex() for k in keys],
      'weak_internal_K1_zero_positions':I.tolist(),
      'weak_internal_subkey_count':'2^64 of 2^128 possible K1 values',
      'weak_internal_subkey_fraction':'2^-64 (NOT a verified genuine master-key fraction)',
      'second_multiset_inner_P3_offset_byte4':offset,
      'negative_control':{
         'model':'synthetic restricted K1 replaced by independent random K1 violating K1[0]=0',
         'violates_weak_K1_condition':True,
         'round4_balanced_byte_counts_over_16':negative_balances,
         'both_multisets_fully_balanced':all(z==16 for z in negative_balances),
         'interpretation':'Empirical diagnostic, not necessity proof'},
      'distinguisher':{'rounds':4,'prewhitening':False,
         'plaintexts_per_multiset':256,'multisets_are_disjoint':True,
         'results':details,'all_16_byte_sums_zero':True},
      'key_filtering':{'target_rounds':5,'plaintexts_total':512,
         'terminal_operation':'column-wise modular addition mod 2^64',
         'correct_K5_terminal_128bit_hex':keys[5].tobytes().hex(),
         'K5_odd_derived_from_K4_rotation_verified':True,
         'K1_odd_derived_from_K0_rotation_verified':True,
         'K3_odd_derived_from_K2_rotation_verified':True,
         'correct_K5_in_tested_candidate_cartesian_product':True,
         'observed_full_K5_combinations_in_tested_product':count,
         'enumerated_K5_K4_tuples_if_at_most_512':tuples,
         'columns':cols,'full_master_key_recovery_claimed':False}}
    if tidx==0:
        record['reproducible_test_vectors']=[
          {'multiset':i,'samples':samples(ps[i],states[i],ctsets[i])}
          for i in (0,1)]
    return record

def base_selftest():
    for size,expected in [(16,'81bf1c7d779bac20e1c9ea39b4d2ad06'),
                          (32,'58ec3e091000158a1148f7166f334f14')]:
        master=np.arange(size,dtype=np.uint8)
        pt=np.arange(size,size+16,dtype=np.uint8)
        kk=expand_key(master)
        require(encrypt(pt,kk).tobytes().hex()==expected,'official encryption KAT failed')
        require(np.array_equal(decrypt(encrypt(pt,kk),kk),pt),'KAT decryption failed')
    for size,ct,expected in [(16,bytes(range(31,15,-1)),'7291ef2b470cc7846f09c2303973dad7'),
                             (32,bytes(range(47,31,-1)),'f36db456cefddfe1b45b5f7030cad996')]:
        master=np.arange(size-1,-1,-1,dtype=np.uint8)
        require(decrypt(np.frombuffer(ct,dtype=np.uint8),expand_key(master)).tobytes().hex()==expected,
                'official decryption KAT failed')
    rng=np.random.default_rng(917284)
    p3=p3_base()
    require(np.array_equal(np.sort(p3[:,I],axis=0),np.broadcast_to(BYTE_VALUES[:,None],(256,8))),
            'componentwise P3 byte permutation failure')
    for trial in range(24):
        state=rng.integers(0,256,(3,16),dtype=np.uint8)
        require(np.array_equal(Finv(F(state)),state),'F inversion failed')
        key=rng.integers(0,256,(3,16),dtype=np.uint8)
        z=add64(state,key)
        require(np.array_equal(sub64(z,key),state),'modular subtraction failed')
        for col in (0,1):
            a=int.from_bytes(state[0,8*col:8*col+8].tobytes(),'little')
            b=int.from_bytes(key[0,8*col:8*col+8].tobytes(),'little')
            require(z[0,8*col:8*col+8].tobytes()==key_from_int(a+b), 'carry validation failed')
        ct=add64(F(state),key[0])
        for col in (0,1):
            good=key[0,8*col:8*col+8]
            zc=sub64(ct[:,8*col:8*col+8],good)
            partial=INV_SBOX[np.arange(8)%4,mix(zc,inverse=True)]
            full=Finv(sub64(ct,key[0]))[:,SR[8*col:8*col+8]]
            require(np.array_equal(partial,full),'true column inverse/full mismatch')
            wrong_full=key[0].copy()
            wrong_full[8*col:8*col+8]^=np.array([1,0,0,0,0,0,0,128],dtype=np.uint8)
            partial_sum=col_inversion_sums(ct[:,8*col:8*col+8],
                                wrong_full[8*col:8*col+8][None,:])[0]
            wrong_recovered=Finv(sub64(ct,wrong_full))[:,SR[8*col:8*col+8]]
            require(np.array_equal(partial_sum,xor_sum(wrong_recovered)),
                    'wrong-key partial inversion does not match full state')
    return {'status':'PASS','published_encryption_KATs':2,
            'published_decryption_KATs':2,'finite_field_inverse_crosschecks':24,
            'modular_carry_borrow_checks':48,
            'correct_and_wrong_partial_inverse_crosschecks':96,
            'exact_inverse_P3_complete_structure':True}




def selftest():
    report=base_selftest()
    rng=np.random.default_rng(20261117)
    ps,offset=two_multisets(rng)
    # P4(0)=F^-1(0) need not be the zero state.
    # Ensure P4 bytes are not incorrectly assigned All solely from inverse MDS.
    props=properties(ps[0])
    keys=synthetic_keys(rng)
    for j,p in enumerate(ps):
        st,detail=states_and_distinguisher(p,keys,0 if j==0 else offset)
        ct=encrypt(p,keys,rounds=5,pre=False)
        require(np.array_equal(Finv(sub64(ct,keys[5])),st[-1]),
                '5-round inverse did not recover X4')
    report.update({'exact_double_inverse_P4':True,
                   'correct_no_prewhitening_model':True,
                   'K1_K3_K5_odd_round_rotation_verified':True,
                   'two_complete_disjoint_multisets':True,
                   'P4_input_marginal_pattern':props,
                   'conditional_4R_16_balanced_bytes':True})
    return report


def atomic_json(path,obj):
    path=Path(path)
    path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_suffix(path.suffix+'.tmp')
    temp.write_text(json.dumps(obj,sort_keys=True,indent=2)+'\n',encoding='utf-8')
    os.replace(temp,path)


def summarize(outdir,cfg):
    alltrials=[json.loads((outdir/'trials'/f'{i:05d}.json').read_text())
               for i in range(cfg['trials'])]
    rows={};wrong_tested=wrong_first=wrong_both=neg_both=neg_total=0
    product_sizes=[]
    for trial in alltrials:
        require(trial['status']=='PASS' and trial['distinguisher']['all_16_byte_sums_zero'],
                'bad saved trial')
        require(all(z['round4_zero_xor_bytes']==16 for z in trial['distinguisher']['results']),
                'nonbalanced four-round distinguisher')
        neg_total+=1
        neg_both+=int(trial['negative_control']['both_multisets_fully_balanced'])
        product_sizes.append(trial['key_filtering']['observed_full_K5_combinations_in_tested_product'])
        for col in trial['key_filtering']['columns']:
            require(col['true_candidate_retained_by_both_multisets'], 'correct key lost')
            u=col['deduplicated_wrong_testing']
            wrong_tested+=u['unique_wrong_candidates_tested']
            wrong_first+=u['unique_wrong_surviving_first_multiset']
            wrong_both+=u['unique_wrong_surviving_both_multisets']
            for name,stat in col['wrong_candidate_families'].items():
                k=(col['column'],name)
                row=rows.setdefault(k,dict(column=col['column'],family=name,
                       evaluations=0,survivors_after_first=0,survivors_after_both=0))
                row['evaluations']+=stat['tested']
                row['survivors_after_first']+=stat['survive_first_multiset']
                row['survivors_after_both']+=stat['survive_both_multisets']
    rrows=sorted(rows.values(),key=lambda row:(row['column'],row['family']))
    with (outdir/'wrong_key_survivors.csv').open('w',newline='') as fh:
        writer=csv.DictWriter(fh,fieldnames=['column','family','evaluations',
                                             'survivors_after_first','survivors_after_both'])
        writer.writeheader();writer.writerows(rrows)
    report={
        'variant':'Kalyna-128/128','trials_requested':cfg['trials'],
        'trials_completed':len(alltrials),
        'key_model':'SYNTHETIC restricted first internal K1, no initial pre-whitening, not demonstrated compatible with actual master keys',
        'genuine_master_keys_tested_in_conditional_attack':0,
        'weak_K1_condition':'K1[i]=0 for i in {0,1,2,3,12,13,14,15}',
        'restricted_subkey_cardinality':'2^64',
        'subkey_fraction':'2^-64 (NOT a demonstrated master-key fraction)',
        'distinguisher':{'rounds':4,'initial_prewhitening':False,
            'plaintext_formula':'P4(x)=F^-1(P3(x)), P3(x)=F^-1(F(0) xor x e7)',
            'plaintexts_per_multiset':256,'disjoint_multisets_per_trial':2,
            'full_multisets_verified':2*cfg['trials'],
            'balanced_byte_positions':16,'positive_trials':cfg['trials'],
            'status':'PASS'},
        'key_filtering':{'target_rounds':5,'chosen_plaintexts_per_trial':512,
            'true_terminal_64bit_column_candidates_retained':2*cfg['trials'],
            'true_K5_in_tested_product_every_trial':True,
            'odd_K5_rotation_to_even_K4_verified':True,
            'sampled_wrong_column_candidate_evaluations_deduplicated_within_trial':wrong_tested,
            'wrong_columns_survived_first_multiset':wrong_first,
            'wrong_columns_survived_both_multisets':wrong_both,
            'max_observed_full_K5_tuples_in_sampled_product':max(product_sizes),
            'per_family_counts':rrows,
            'scope_note':'Wrong 64-bit columns sampled, NOT exhaustive 2^64. No master-key recovery or global uniqueness claim.',
            'full_master_key_recovery_claimed':False},
        'nonweak_key_negative_controls':{
            'trials':neg_total,'both_multisets_fully_balanced':neg_both,
            'scope':'Deliberate K1 condition violation; empirical control only'},
        'nominal_work_from_paper':'2^74 column partial-decryption operations, NOT measured encryptions',
        'result':'PASS'}
    atomic_json(outdir/'summary.json',report)
    first=alltrials[0]
    atomic_json(outdir/'reproducible_test_vectors.json',{
        'key_model':report['key_model'],
        'K0_unapplied_K1_K2_K3_K4_K5_hex':first['keys_K0_unapplied_K1_K2_K3_K4_K5_hex'],
        'weak_internal_K1_zero_positions':I.tolist(),
        'second_multiset_inner_P3_offset_byte4':first['second_multiset_inner_P3_offset_byte4'],
        'vectors':first['reproducible_test_vectors']})
    textlines=['# Kalyna-128/128: 4-round no-prewhitening conditional integral and 5-round filtering','',
        '## Stage 1 — 4-round integral distinguisher',
        f'- Completed {cfg["trials"]}/{cfg["trials"]} trials; two complete disjoint 256-text multisets each',
        '- 16/16 bytes at internal X4 balanced on every multiset',
        '- Exact P4(x)=F^-1(P3(x)), P3(x)=F^-1(F(0) xor x e7)',
        '- Second multiset: F^-1(P3(x) xor a e4), a nonzero, NOT P4(x) xor a e4',
        '- **NO initial pre-whitening**; K1 zero on I={0,1,2,3,12,13,14,15}',
        '- Synthetic restricted first internal round subkeys; no claim of compatible master keys',
        f'- Negative control: {neg_both}/{neg_total} random K1-violating configurations balanced on BOTH structures',
        '- Negative control does not prove the restriction is necessary',
        '', '## Stage 2 — 5-round terminal-key candidate filtering',
        f'- Correct K5 key columns retained: {2*cfg["trials"]}/{2*cfg["trials"]}',
        '- True K5 appears in sampled per-column Cartesian product; derived K4 is the correct predecessor',
        '- Genuine *rotation rule* K5=Rot(K4), but no genuine nonlinear master-key expansion is claimed',
        '- 5-round ciphertext has terminal 64-bit modular addition; partial inverse includes borrow',
        '- Data per trial: two 256-plaintext structures, total 2^9 chosen plaintexts',
        '- Paper nominal work: 2^74 64-bit column partial-decryption operations, NOT full encryptions',
        '', '### Incorrect terminal subkey columns (sampled and structured)',
        f'- Distinct wrong-column evaluations within each trial/column: {wrong_tested}',
        f'- Survive first multiset: {wrong_first}',
        f'- Survive both multisets: {wrong_both}',
        '| Column | Family | Evaluations | Survive first | Survive both |',
        '|---|---|---:|---:|---:|']
    for row in rrows:
        textlines.append(f'| {row["column"]} | {row["family"]} | {row["evaluations"]} | {row["survivors_after_first"]} | {row["survivors_after_both"]} |')
    textlines += ['',
      'Wrong-key families can overlap; deduplicated totals are separate and per trial/column.',
      'No exhaustive 2^64 search, false-positive rate, key uniqueness, or master-key recovery is established.',
      'The numerical samples and all five-round internal states are saved in reproducible_test_vectors.json.', '']
    (outdir/'REPORT.md').write_text('\n'.join(textlines),encoding='utf-8')
    return report


def main():
    parser=argparse.ArgumentParser(description='Kalyna-128/128 4R conditional no-PW integral + 5R subkey filtering')
    parser.add_argument('--trials',type=int,default=1000)
    parser.add_argument('--random-wrong',type=int,default=64)
    parser.add_argument('--jobs',type=int,default=4)
    parser.add_argument('--chunk-size',type=int,default=48)
    parser.add_argument('--seed',type=int,default=20261117)
    parser.add_argument('--no-full-msb',action='store_true')
    parser.add_argument('--out',type=Path,default=Path('KALYNA128_128_R5_COMBINED_RESULTS'))
    parser.add_argument('--resume',action='store_true')
    parser.add_argument('--self-test',action='store_true')
    parser.add_argument('--progress-every',type=int,default=50)
    args=parser.parse_args()
    if min(args.trials,args.jobs,args.chunk_size,args.progress_every)<1 or args.random_wrong<0 or args.seed<0:
        parser.error('trials/jobs/chunk/progress positive; wrong candidates and seed nonnegative')
    print('KALYNA-128/128: 4-round NO-PW weak-K1 integral + 5-round terminal-subkey filtering',flush=True)
    print('[self-test] Official cipher KAT, F inversions, carry/borrow, P4 exact input, partial inverse',flush=True)
    tests=selftest()
    print('[self-test] '+tests['status'],flush=True)
    if args.self_test:
        print(json.dumps(tests,indent=2));return 0
    cfg={'trials':args.trials,'random_wrong':args.random_wrong,
         'chunk_size':args.chunk_size,'seed':args.seed,'full_msb':not args.no_full_msb}
    script=Path(__file__)
    config={'parameters':cfg,'source_file':script.name,
       'source_sha256':hashlib.sha256(script.read_bytes()).hexdigest(),
       'numpy':np.__version__,'version':VERSION}
    output=args.out
    cfgpath=output/'config.json'
    if args.resume:
        require(cfgpath.exists(),'missing config for resume')
        require(json.loads(cfgpath.read_text())==config,
                'resume denied: source file or cryptographic parameters changed')
    else:
        require(not output.exists() or not any(output.iterdir()),
                'output directory not empty: use --resume or a new --out')
    (output/'trials').mkdir(parents=True,exist_ok=True)
    atomic_json(cfgpath,config)
    atomic_json(output/'selftest.json',tests)
    atomic_json(output/'environment.json',{'python':sys.version,'platform':platform.platform(),
                                            'numpy':np.__version__})
    pending=[]
    for i in range(args.trials):
        trialfile=output/'trials'/f'{i:05d}.json'
        if trialfile.exists():
            old=json.loads(trialfile.read_text())
            require(old['trial']==i and old['status']=='PASS','invalid saved trial')
        else: pending.append(i)
    done_count=args.trials-len(pending)
    print(f'[config] {args.trials} trials, completed={done_count}, pending={len(pending)}, jobs={args.jobs}, '
          f'random_wrong={args.random_wrong}, full_255_MSB={not args.no_full_msb}',flush=True)
    print('[STAGE 1] 4-round no-prewhitening conditional integral, P4=F^-1(P3), 16 balanced bytes',flush=True)
    print('[STAGE 2] 5-round terminal modular addition; true K5 columns + sampled wrong guesses',flush=True)
    print('[key model] synthetic restricted K1; K1/K3/K5 obey odd-round rotation; no master-key claim',flush=True)
    start=time.monotonic();latest=start
    def save(record):
        nonlocal done_count,latest
        atomic_json(output/'trials'/f'{record["trial"]:05d}.json',record)
        done_count+=1
        now=time.monotonic()
        if record['trial']==0 or done_count%args.progress_every==0 or done_count==args.trials or now-latest>=25:
            dat=record['distinguisher']['results']
            survivors=sum(z['deduplicated_wrong_testing']['unique_wrong_surviving_both_multisets']
                          for z in record['key_filtering']['columns'])
            print(f'[progress {done_count}/{args.trials}, elapsed={now-start:.1f}s] '
                  f'DIST=({dat[0]["round4_zero_xor_bytes"]}/16,{dat[1]["round4_zero_xor_bytes"]}/16), '
                  f'K5 true cols=2/2, sampled wrong survivors={survivors}',flush=True)
            latest=now
        if record['trial']==0:
            dat=record['distinguisher']['results'][0]
            print(f'  [trial 0 DIST] P4={dat["input"]}, X1={dat["round1"]}, '
                  f'X2={dat["round2"]}, X3={dat["round3"]}, X4={dat["round4"]}',flush=True)
            print('  [trial 0 FILTER] K5='+record['key_filtering']['correct_K5_terminal_128bit_hex'],flush=True)
            for z in record['key_filtering']['columns']:
                print(f'  [trial 0] column={z["column"]}, I_j={z["index_set_Ij"]}, '
                      f'true={z["true_terminal_64bit_key_hex"]}, '
                      f'wrong_survivors={z["deduplicated_wrong_testing"]["unique_wrong_surviving_both_multisets"]}',flush=True)
    if args.jobs==1:
        for i in pending:save(one_trial(i,cfg))
    else:
        with ProcessPoolExecutor(max_workers=args.jobs) as pool:
            futures={pool.submit(one_trial,i,cfg):i for i in pending}
            while futures:
                completed,_=wait(futures,timeout=25,return_when=FIRST_COMPLETED)
                for f in completed:
                    try:save(f.result())
                    except Exception:
                        print('[FAILED] '+str(futures[f]),flush=True)
                        raise
                    del futures[f]
                if not completed:
                    print(f'[heartbeat] elapsed={time.monotonic()-start:.1f}s completed={done_count}',flush=True)
    final=summarize(output,cfg)
    print(f'[COMPLETE] 4R distinguisher {final["distinguisher"]["positive_trials"]}/{args.trials}, '
          f'correct K5 columns {final["key_filtering"]["true_terminal_64bit_column_candidates_retained"]}/{2*args.trials}',flush=True)
    print(f'[wrong column candidates] sampled={final["key_filtering"]["sampled_wrong_column_candidate_evaluations_deduplicated_within_trial"]}, '
          f'survive both={final["key_filtering"]["wrong_columns_survived_both_multisets"]}',flush=True)
    print('[files] '+str(output)+'/REPORT.md, summary.json, vectors, trials/',flush=True)
    print('[scope] restricted K1 synthetic model; no exhaustive recovery/master-key validation',flush=True)
    return 0


if __name__=='__main__':
    raise SystemExit(main())
