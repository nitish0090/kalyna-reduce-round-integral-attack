#!/usr/bin/env python3
"""Kalyna-512/512: 5-round conditional integral + 6-round key-column filter.

Standalone research validation based on updated manuscript Sec. 5.3/Table 2.
State: 8 x 8 bytes, column-major, little-endian 64-bit words.
Initial pre-whitening is OMITTED. K1 must have eight zero bytes. K1..K5
are XOR round additions and K6 is terminal modulo-2^64 addition.
The balanced state is X5 BEFORE terminal modular addition, NOT ciphertext.

The 2^64 key-column search is NOT exhaustive, and no master-key recovery
is claimed. Two complete, distinct 256-plaintext structures per trial.
IMPORTANT: Synthetic restricted subkeys are NOT genuine master-key expansions.
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

VERSION = '1.0-512-r6-weak-K1-no-PW'
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
BLOCK_BYTES = 64
COLS = 8
ROWS = 8
ROUNDS = 18
SHIFT = np.arange(8, dtype=np.intp)
# Forward SR maps each output byte to the original (source) byte.
SR = np.array([8*((c-int(SHIFT[r]))%8)+r
               for c in range(COLS) for r in range(ROWS)], dtype=np.intp)
IS = np.argsort(SR)
I_SETS = [tuple(int(SR[8*j+r]) for r in range(8)) for j in range(8)]


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
    # Official RotateLeft: 2*nb+3 = 19 bytes for 512-bit state.
    return np.roll(a8(k),-19,axis=-1)


def even_from_odd(k):
    return np.roll(a8(k),19,axis=-1)


def expand_key(master):
    """Exact 512/512 Kalyna schedule, 19 x 512-bit subkeys K[0]..K[18]."""
    key=a8(master)
    if key.shape!=(64,): raise ValueError('512-bit key required')
    s=np.zeros(64,dtype=np.uint8)
    s[0]=8+8+1
    kt=F(add64(F(F(add64(s,key))^key),key))
    keys=np.empty((19,64),dtype=np.uint8)
    tmv=np.tile(np.array([1,0,1,0,1,0,1,0],dtype=np.uint8),8)
    data=key.copy()
    for r in range(0,19,2):
        tmp=add64(kt,tmv)
        keys[r]=add64(F(F(add64(data,tmp))^tmp),tmp)
        if r<18:
            tmv=add64(tmv,tmv)
            data=np.roll(data,-8)  # official Rotate: one 64-bit word
    for r in range(1,18,2):
        keys[r]=odd_from_even(keys[r-1])
    return keys




def full_encrypt(plaintext,keys):
    assert keys.shape==(19,64)
    x=add64(plaintext,keys[0])
    for r in range(1,18):
        x=F(x)^keys[r]
    return add64(F(x),keys[18])


def full_decrypt(ciphertext,keys):
    x=Finv(sub64(ciphertext,keys[18]))
    for r in range(17,0,-1):
        x=Finv(x^keys[r])
    return sub64(x,keys[0])


def verify_primitives():
    # Authors' 512/512 vector from main.c of Kalyna-reference, order is LE words.
    master=np.arange(64,dtype=np.uint8)
    plaintext=np.arange(64,128,dtype=np.uint8)
    expected=('4a26e31b811c356a'+'a61dd6ca0596231a'+'67ba8354aa47f3a1'+
              '3e1deec320eb56b8'+'95d0f417175bab66'+'2fd6f134bb15c86c'+
              'cb906a26856efeb7'+'c5bc6472940dd9d9')
    keys=expand_key(master)
    c=full_encrypt(plaintext,keys)
    assert c.tobytes().hex()==expected,(c.tobytes().hex(),expected)
    assert np.array_equal(full_decrypt(c,keys),plaintext)
    assert np.array_equal(keys[3],odd_from_even(keys[2]))
    rng=np.random.default_rng(984721)
    for _ in range(5):
        x=rng.integers(0,256,(7,64),dtype=np.uint8)
        k=rng.integers(0,256,64,dtype=np.uint8)
        assert np.array_equal(Finv(F(x)),x)
        assert np.array_equal(sub64(add64(x,k),k),x)
        assert np.array_equal(even_from_odd(odd_from_even(k)),k)
    assert len(I_SETS)==8 and set().union(*map(set,I_SETS))==set(range(64))
    assert set(I_SETS[0])=={8*((-r)%8)+r for r in range(8)}
    return dict(official_512_512_encryption='PASS',official_512_512_decryption='PASS',
                key=master.tobytes().hex(),plaintext=plaintext.tobytes().hex(),
                expected_ciphertext=expected,full_key_schedule='PASS',
                round_function_inverse='PASS',modular_carry_and_borrow='PASS',
                odd_even_rotation='PASS',shiftrows_column_sets=[list(q) for q in I_SETS])


def xorsum(x):
    return np.bitwise_xor.reduce(a8(x),axis=0)


# ============================================================================
# Revised manuscript Sec. 5.3 (5R distinguisher) / Table 2 (6R filter).
# Exact condition K^(1)[i] == 0 at these EIGHT positions. NO PRE-WHITENING.
# ============================================================================
WEAK_INDEX=(0,15,22,29,36,43,50,57)
ACTIVE_BYTE=7
OFFSET_BYTE=1  # P4(x)[1] = 0 for all x; safe to change before final F^-1
N=256


def define_backward_structures():
    """P4=F^-1(F(0) xor x e7), P5=F^-1(P4).

    Important: P5 may vary in many bytes; no independent 8-byte active
    structure is substituted. The 8 varying P4 bytes are correlated.
    """
    zero=np.zeros(64,dtype=np.uint8)
    q=np.broadcast_to(F(zero),(N,64)).copy()
    q[:,ACTIVE_BYTE]^=np.arange(256,dtype=np.uint8)
    p4=Finv(q)
    assert np.array_equal(F(p4),q)
    assert np.unique(p4,axis=0).shape[0]==N
    assert set(np.flatnonzero(np.any(p4!=0,axis=0)).tolist())==set(WEAK_INDEX)
    assert all(np.unique(p4[:,i]).size==N for i in WEAK_INDEX)
    assert np.all(p4[:,OFFSET_BYTE]==0) and not np.any(p4[0])
    p5=Finv(p4)
    assert np.array_equal(F(p5),p4)
    assert np.unique(p5,axis=0).shape[0]==N
    p4.flags.writeable=False
    p5.flags.writeable=False
    return p4,p5


BASE_P4,BASE_P5=define_backward_structures()


def chosen_structures(rng):
    """Two disjoint 256-plaintext sets preserving the exact P4 support.

    P5,a(x)=F^-1(P4(x) xor a*e1), not P5(x) xor a*e1.
    """
    a=int(rng.integers(1,256))
    shifted=BASE_P4.copy()
    shifted[:,OFFSET_BYTE]^=np.uint8(a)
    p5_shifted=Finv(shifted)
    assert np.array_equal(F(p5_shifted),shifted)
    assert np.all(shifted[:,OFFSET_BYTE]==a)
    assert np.unique(p5_shifted,axis=0).shape[0]==N
    assert not np.any(np.all(BASE_P5[:,None,:]==p5_shifted[None,:,:],axis=-1))
    return [BASE_P5,p5_shifted],a


def synthetic_weak_subkeys(rng):
    """K0 is an UNAPPLIED schedule placeholder, NOT pre-whitening.

    Set K1 weak directly. Enforce the exact Kalyna odd-key rotations
    K1=Rot(K0), K3=Rot(K2), K5=Rot(K4). K6 is even and independent.
    This is not proof of compatibility with a full master-key expansion.
    """
    k=rng.integers(0,256,(7,64),dtype=np.uint8)
    k[1,list(WEAK_INDEX)]=0
    k[0]=even_from_odd(k[1])  # do NOT apply K0 to plaintexts
    k[3]=odd_from_even(k[2])
    k[5]=odd_from_even(k[4])
    return k


def forward6_without_prewhitening(p,k):
    """X1=F(P) xor K1; ...; X5=F(X4) xor K5; C=F(X5) + K6.

    There is NO call to add64(p,K0) at the input.
    """
    states=[]
    z=p
    for r in range(1,6):
        z=F(z)^k[r]
        states.append(z)
    ciphertext=add64(F(z),k[6])
    return states,ciphertext


def verify_integral(ps,k,a):
    assert k.shape==(7,64)
    assert not np.any(k[1,list(WEAK_INDEX)]), 'INVALID: weak K1 indices must all be zero'
    for i in (1,3,5):
        assert np.array_equal(k[i],odd_from_even(k[i-1])),('wrong odd-round rotation',i)
    outputs=[]
    for mid,p in enumerate(ps):
        assert p.shape==(N,64)
        p4=F(p)
        assert np.all(p4[:,OFFSET_BYTE]==(0 if mid==0 else a))
        varying=set(np.flatnonzero(np.any(p4!=p4[0],axis=0)).tolist())
        assert varying==set(WEAK_INDEX),('wrong P4 active support',varying)
        assert all(np.unique(p4[:,i]).size==N for i in WEAK_INDEX)
        states,c=forward6_without_prewhitening(p,k)
        x1,x2,x3,x4,x5=states
        assert np.array_equal(x1,p4^k[1]), 'Unwanted initial pre-whitening applied'
        # Exact disjoint-support identity, including the optional offset.
        const=k[1].copy()
        if mid:const[OFFSET_BYTE]^=np.uint8(a)
        x2_expected=np.broadcast_to(F(const)^k[2],(N,64)).copy()
        x2_expected[:,ACTIVE_BYTE]^=np.arange(256,dtype=np.uint8)
        assert np.array_equal(x2,x2_expected), 'K1 restriction not propagated exactly'
        assert np.unique(x2[:,ACTIVE_BYTE]).size==N
        assert np.all(x2[:,np.arange(64)!=ACTIVE_BYTE]==x2[0,np.arange(64)!=ACTIVE_BYTE])
        for byte in range(64):
            n3=np.unique(x3[:,byte]).size
            expected=256 if byte>=56 else 1
            assert n3==expected,('round3 A/C',byte,n3,expected)
            assert np.unique(x4[:,byte]).size==256,('round4 All',byte)
        assert not np.any(xorsum(x5)), '5R internal balance failure'
        assert np.array_equal(Finv(sub64(c,k[6])),x5), '6R correct-key inversion failed'
        outputs.append((states,c))
    return outputs


def get_col_u64(ciphertexts,j):
    c=np.ascontiguousarray(np.stack([s[:,8*j:8*j+8] for s in ciphertexts]))
    return c.view('<u8').reshape(2,256)


def get_key_col_u64(k,j):
    return int(np.ascontiguousarray(k[8*j:8*j+8]).view('<u8')[0])


def column_filter_exact(cts,j,key_col):
    # Reconstruct each KEYED column, but do NOT interpret inverse ShiftRows
    # as acting on a single column. The eight inverse-Sbox outputs lie at I_j.
    c=np.ascontiguousarray(np.stack([z[:,8*j:8*j+8] for z in cts]))
    y=mix(sub64(c,key_col),True)
    pre_sr=INV_SBOX[np.arange(8)%4,y]
    sums=np.bitwise_xor.reduce(pre_sr,axis=1)
    return bool(np.all(sums==0)),sums


def guess_filter_fast(ct_u64,guess_ints,batch=32):
    # Compare guesses with full 64-bit modular subtraction, automatic carries.
    # Early rejection after FIRST inverse-Sbox sum, but identical final predicate
    # to column_filter_exact for every admitted candidate.
    all_survivors=[]
    first_total=0
    for start in range(0,len(guess_ints),batch):
        q=np.asarray(guess_ints[start:start+batch],dtype='<u8')
        dec=np.ascontiguousarray(ct_u64[None,:,:]-q[:,None,None]).view(np.uint8).reshape(len(q),2,256,8)
        active=np.arange(len(q))
        for textset in (0,1):
            for row in range(8):
                if len(active)==0:break
                arr=dec[active,textset,:,:]
                lin=np.zeros((len(active),256),dtype=np.uint8)
                for b in range(8):
                    lin^=GF[IMDS[row,b],arr[:,:,b]]
                inv=INV_SBOX[row%4,lin]
                ok=np.bitwise_xor.reduce(inv,axis=1)==0
                active=active[ok]
            if textset==0:
                first_total+=len(active)
            if len(active)==0:break
        all_survivors.extend(int(q[i]) for i in active)
    return all_survivors,first_total,len(guess_ints)


def make_wrong_keys(true_int,rng,trial,col,random_wrong,single_bit_wrong,msb_differences,full_msb):
    true_int=int(true_int)
    candidates=set()
    def add(v):
        v=int(v)&((1<<64)-1)
        if v!=true_int:candidates.add(v)
    for _ in range(random_wrong):
        add(int.from_bytes(rng.bytes(8),'little'))
    for t in range(min(single_bit_wrong,64)):
        add(true_int^(1<<((trial*31+col*17+t*13)%64)))
    if full_msb:
        for d in range(1,256):add(true_int^(d<<56))
    else:
        for t in range(min(msb_differences,255)):
            add(true_int^((1+(trial*29+col*43+t*37)%255)<<56))
    # Carry-oriented alternatives and a few structured byte modifications.
    for d in (1,-1,0x100,-0x100,1<<56,-(1<<56),1<<63):
        add(true_int+d)
    for i in (0,7):
        for d in (1,255):
            add(true_int^(d<<(8*i)))
    return sorted(candidates)




def run_trial(trial,seed,random_wrong,single_bit_wrong,msb_differences,full_msb_trials,nonweak_controls):
    rng=np.random.default_rng(np.random.SeedSequence([int(seed),int(trial),5125126]))
    keys=synthetic_weak_subkeys(rng)
    ps,a=chosen_structures(rng)
    data=verify_integral(ps,keys,a)
    cts=[item[1] for item in data]
    retained=0
    wrong_tested=first=both=0
    survivors=[]
    for j in range(8):
        real=keys[6,8*j:8*(j+1)]
        passed,sums=column_filter_exact(cts,j,real)
        if not passed:
            raise AssertionError(('Correct K6 column rejected',j,sums.tolist()))
        retained+=1
        wrong=make_wrong_keys(get_key_col_u64(keys[6],j),rng,trial,j,
            random_wrong,single_bit_wrong,msb_differences,trial<full_msb_trials)
        ss,ff,num=guess_filter_fast(get_col_u64(cts,j),wrong)
        for guess in ss:
            gb=np.frombuffer(int(guess).to_bytes(8,'little'),dtype=np.uint8)
            direct,_=column_filter_exact(cts,j,gb)
            assert direct, 'Fast candidate filter disagrees with direct inversion'
            survivors.append(dict(trial=trial,column=j,wrong_candidate_hex=gb.tobytes().hex()))
        first+=ff
        both+=len(ss)
        wrong_tested+=num
    # Deliberately violate K1, keep NO pre-whitening, repair its rotated K0
    # placeholder. A violation removes the theorem, but doesn't imply every
    # particular nonweak multiset must fail; record observed failures only.
    negative_total=negative_balanced_both=0
    if trial<nonweak_controls:
        for i in WEAK_INDEX:
            bad=keys.copy()
            bad[1,i]=np.uint8(1+((trial+17*i)%255))
            bad[0]=even_from_odd(bad[1])
            bb=[]
            for p in ps:
                states,_=forward6_without_prewhitening(p,bad)
                bb.append(bool(not np.any(xorsum(states[4]))))
            negative_total+=1
            negative_balanced_both+=int(all(bb))
    record=dict(trial=trial,seed=int(seed),model='synthetic restricted round subkeys',
         initial_pre_whitening='OMITTED',
         pre_whitening_applied=False,
         weak_subkey_condition='K^(1)[i] = 0 for i in {0,15,22,29,36,43,50,57}',
         weak_K1_byte_indices=list(WEAK_INDEX),weak_K1_bytes_zero=True,
         master_key_expansion_compatibility='NOT ESTABLISHED',
         second_multiset_P4_offset_at_byte1=a,
         second_multiset_construction='F^-1(P4(x) XOR a*e_1)',
         chosen_plaintexts=512,multisets=2,multiset_size=256,
         distinguisher_rounds=5,filter_target_rounds=6,balanced_bytes_each=64,
         both_5round_distinguishers_pass=True,
         correct_K6_columns_retained=retained,
         no_K6_to_K5_rotation_assumed=True,
         wrong_column_candidate_evaluations=wrong_tested,
         wrong_first_multiset_survivors=first,
         wrong_both_multiset_survivors=both,
         nonweak_controls_tested=negative_total,
         nonweak_controls_balanced_both=negative_balanced_both,
         full_msb_255_per_column=trial<full_msb_trials)
    vectors=None
    if trial==0:
        vectors=dict(
          condition='no initial pre-whitening; K1[i]=0 at I',
          weak_K1_byte_indices=list(WEAK_INDEX),
          subkeys_K0_placeholder_through_K6=[t.tobytes().hex() for t in keys],
          K0_is_unapplied_placeholder=True,
          synthetic_not_master_expanded=True,
          exact_backward_definition='P5(x)=F^-1(F^-1(F(0) XOR x*e7))',
          exact_second_structure='F^-1(P4(x) XOR a*e1)',
          second_offset_a=a,correct_terminal_key_K6=keys[6].tobytes().hex(),
          K5_is_from_K4_not_K6=True,
          inverse_sr_sets=[list(q) for q in I_SETS],
          official_reference=verify_primitives(),two_multisets=[])
        for p,(states,c) in zip(ps,data):
            x1,x2,x3,x4,x5=states
            vectors['two_multisets'].append(dict(
              plaintext_set_sha256=hashlib.sha256(p.tobytes()).hexdigest(),
              ciphertext_set_sha256=hashlib.sha256(c.tobytes()).hexdigest(),
              first_plaintext=p[0].tobytes().hex(),last_plaintext=p[-1].tobytes().hex(),
              first_ciphertext=c[0].tobytes().hex(),last_ciphertext=c[-1].tobytes().hex(),
              first_F_plaintext=F(p[0]).tobytes().hex(),
              first_X1=x1[0].tobytes().hex(),first_X2=x2[0].tobytes().hex(),
              first_X3=x3[0].tobytes().hex(),first_X4=x4[0].tobytes().hex(),
              first_X5=x5[0].tobytes().hex(),
              XOR_sum_X5=xorsum(x5).tobytes().hex(),
              XOR_sum_ciphertext=xorsum(c).tobytes().hex()))
    return record,survivors,vectors


def main():
    p=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument('--trials',type=int,default=1000)
    p.add_argument('--seed',type=int,default=20261117)
    p.add_argument('--jobs',type=int,default=4)
    p.add_argument('--random-wrong',type=int,default=4)
    p.add_argument('--single-bit-wrong',type=int,default=4)
    p.add_argument('--msb-differences',type=int,default=4)
    p.add_argument('--full-msb-trials',type=int,default=3)
    p.add_argument('--nonweak-controls',type=int,default=20)
    p.add_argument('--progress-every',type=int,default=100)
    p.add_argument('--out',default='KALYNA512_512_R6_RESULTS')
    p.add_argument('--resume',action='store_true')
    args=p.parse_args()
    if args.trials<1 or args.jobs<1 or args.progress_every<1 or any(
        getattr(args,k)<0 for k in ('random_wrong','single_bit_wrong','msb_differences',
                                   'full_msb_trials','nonweak_controls')):
        p.error('Invalid argument: negative samples or nonpositive trials/jobs/progress')
    root=Path(args.out);root.mkdir(parents=True,exist_ok=True)
    compute={k:getattr(args,k) for k in ('trials','seed','random_wrong','single_bit_wrong',
                                        'msb_differences','full_msb_trials','nonweak_controls')}
    sha=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    config=root/'settings.json'
    if args.resume:
        if not config.exists():raise FileNotFoundError('Missing settings.json for resume')
        prior=json.loads(config.read_text())
        if prior['args']!=compute or prior['source_sha256']!=sha:
            raise ValueError('Code or settings changed; refusing inconsistent resume')
    else:
        if config.exists():raise FileExistsError('Existing run: pass --resume')
        config.write_text(json.dumps(dict(args=compute,source_sha256=sha,version=VERSION,
            python=sys.version,numpy=np.__version__,platform=platform.platform(),
            official_reference_repo=REFERENCE,reference_commit=REFERENCE_COMMIT),indent=2))
    selftest=verify_primitives()
    (root/'official_known_answer.json').write_text(json.dumps(selftest,indent=2))
    records={}
    if args.resume and (root/'trials.jsonl').exists():
        for line in (root/'trials.jsonl').read_text().splitlines():
            if not line.strip():continue
            item=json.loads(line)
            if item['trial'] in records:raise AssertionError('Duplicate completed trial')
            records[item['trial']]=item
    missing=[i for i in range(args.trials) if i not in records]
    start=time.perf_counter()
    print('Kalyna-512/512: no initial pre-whitening; weak K1 5R -> 6R column filter',flush=True)
    print('K1[i]=0 for',WEAK_INDEX,flush=True)
    print('P5(x)=F^-1(P4(x)), P4(x)=F^-1(F(0) xor x*e7)',flush=True)
    print('Second P5,a(x)=F^-1(P4(x) xor a*e1), a!=0; disjoint',flush=True)
    print('K6 is EVEN; no invalid K6->K5 rotation. Synthetic subkeys only.',flush=True)
    print('Official 512/512 encryption/decryption KAT PASS',flush=True)
    print(f'Required {args.trials} trials; missing {len(missing)}; 2x256 plaintexts',flush=True)
    def save(result):
        d,surv,vec=result
        if d['trial'] in records:raise AssertionError('Duplicate completed trial')
        records[d['trial']]=d
        with (root/'trials.jsonl').open('a') as f:f.write(json.dumps(d,sort_keys=True)+'\n')
        if surv:
            with (root/'wrong_key_survivors.jsonl').open('a') as f:
                for item in surv:f.write(json.dumps(item,sort_keys=True)+'\n')
        if vec is not None:
            (root/'reproducible_test_vectors.json').write_text(json.dumps(vec,indent=2))
        n=len(records)
        if n%args.progress_every==0 or n==args.trials:
            totalwrong=sum(z['wrong_column_candidate_evaluations'] for z in records.values())
            totalboth=sum(z['wrong_both_multiset_survivors'] for z in records.values())
            print(f'Progress {n}/{args.trials}, valid multisets {2*n}, correct K6 columns {8*n}, '
                  f'wrong evaluated {totalwrong}, wrong survivors {totalboth}, '
                  f'elapsed {time.perf_counter()-start:.2f}s',flush=True)
    if args.jobs==1:
        for i in missing:
            save(run_trial(i,args.seed,args.random_wrong,args.single_bit_wrong,
                           args.msb_differences,args.full_msb_trials,args.nonweak_controls))
    else:
        with ProcessPoolExecutor(max_workers=args.jobs) as pool:
            fut={pool.submit(run_trial,i,args.seed,args.random_wrong,args.single_bit_wrong,
                             args.msb_differences,args.full_msb_trials,args.nonweak_controls):i
                 for i in missing}
            for done in as_completed(fut):save(done.result())
    assert len(records)==args.trials
    recs=[records[i] for i in range(args.trials)]
    with (root/'trial_summary.csv').open('w',newline='') as f:
        cw=csv.DictWriter(f,fieldnames=list(recs[0]));cw.writeheader();cw.writerows(recs)
    sums=lambda field:sum(d[field] for d in recs)
    assert all(d['both_5round_distinguishers_pass'] and d['correct_K6_columns_retained']==8
               and d['pre_whitening_applied']==False for d in recs)
    result=dict(variant='Kalyna-512/512',distinguisher_rounds=5,target_rounds=6,
        trials=args.trials,multisets=2*args.trials,chosen_plaintexts_per_trial=512,
        first_internal_round_weak_bytes=list(WEAK_INDEX),initial_pre_whitening='OMITTED',
        weak_first_subkey_fraction='2^-64',synthetic_round_key_model=True,
        key_schedule_compatible_master_keys='NOT VERIFIED',
        correct_K6_column_retention=sums('correct_K6_columns_retained'),
        correct_columns_expected=8*args.trials,
        wrong_columns_evaluated=sums('wrong_column_candidate_evaluations'),
        wrong_first_multiset_survivors=sums('wrong_first_multiset_survivors'),
        wrong_both_multiset_survivors=sums('wrong_both_multiset_survivors'),
        nonweak_controls=sums('nonweak_controls_tested'),
        nonweak_controls_balanced_both=sums('nonweak_controls_balanced_both'),
        official_cipher_vectors='PASS',
        analytic_work='2^76 64-bit column partial-decryption operations (not measured exhaustively)',
        elapsed_seconds=time.perf_counter()-start)
    (root/'summary.json').write_text(json.dumps(result,indent=2))
    (root/'REPORT.md').write_text(f'''# Kalyna-512/512 six-round filtering, 1,000-trial validation

## Exact paper model (revised Section 5.3, Table 2)

- **NO initial pre-whitening**. A generated K0 is an **unapplied**
  scheduling placeholder to maintain the conventional K1=RotL(K0) relation.
- **Required first internal XOR subkey:** K^(1)[i]=0 for all
  i in {{0,15,22,29,36,43,50,57}}. Exactly eight zero bytes; fraction
  2^-64 among unconstrained 512-bit first-round subkeys. All other K1 bytes
  are unrestricted. No other weak-key conditions are imposed.
- Base: P4(x)=F^-1(F(0) XOR x e7), P5(x)=F^-1(P4(x)).
- Disjoint second valid structure: P5,a(x)=F^-1(P4(x) XOR a e1), a!=0.
  The offset belongs **inside the last inverse F**, not to an arbitrary
  byte translation of P5. Each structure enumerates all x=0..255.
- The eight varying bytes of P4 are correlated functions of x.
- Internal rounds 1..5 end with XOR keys K1..K5. Then C=F(X5)+K6 modulo
  2^64 independently in all eight columns, with **K6 even**.
- Correct-key inversion is X5=F^-1(C-K6). K6 is NOT obtained by rotating K5.
  K1=RotL(K0), K3=RotL(K2), K5=RotL(K4) are checked but K0 is never applied.
- These are **synthetic restricted round subkeys**, not keys certified
  compatible with an actual 512-bit master-key expansion.

## Completed results

| Property | Value |
|---|---:|
| Trials passed | {args.trials}/{args.trials} |
| Complete 256-plaintext multisets balanced at internal X5 | {2*args.trials} |
| Balanced internal bytes per multiset | 64/64 |
| Correct K6 64-bit columns retained | {result['correct_K6_column_retention']}/{8*args.trials} |
| Tested incorrect 64-bit column candidates | {result['wrong_columns_evaluated']} |
| Incorrect candidates passing first structure | {result['wrong_first_multiset_survivors']} |
| Incorrect candidates passing both structures | {result['wrong_both_multiset_survivors']} |
| Deliberately invalid K1 controls | {result['nonweak_controls']} |
| Controls balanced in BOTH structures | {result['nonweak_controls_balanced_both']} |
| Official full-cipher 512/512 reference KAT | PASS |

## Limitations

The incorrect-key search is sampled, not exhaustive over all 2^64
terminal-key column values. The nominal 2^76 work from Table 2 is an
analytical estimate of 64-bit column partial decryptions, not measured
full-block encryption work. No complete master-key-recovery claim is made.
Compatibility of the restricted K1 with an actual 512-bit master-key
expansion has NOT been established. Nonweak controls test failures
empirically; weak-key sufficiency does not imply a converse.
''')
    print('SUCCESS:',json.dumps(result,sort_keys=True),flush=True)


if __name__=='__main__':
    main()
