#!/usr/bin/env python3
"""Kalyna-512/512: conditional 4-round integral + 5-round filtering.

Standalone research validation based on updated manuscript Sec. 5.2/Table 2.
State: 8 x 8 bytes, column-major, little-endian 64-bit words.
K0 is modular pre-whitening with 8 REQUIRED zero bytes. K1..K4 XOR at the
ends of internal rounds. K5 is terminal modular addition. The balanced
state is X4 BEFORE terminal modular addition, not the ciphertext.

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

VERSION = '1.0-512-r5-weak-pw'
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
# Section 5.2 / Table 2: 4R backward extension, weak Kpw, 5R Algorithm 2.
# ============================================================================
WEAK_INDEX=(0,15,22,29,36,43,50,57)
INPUT_VARIABLE=7
OFFSET_BYTE=1  # byte 1 is above variable byte 0 in column 0
N=256


def inverse_defined_plaintexts():
    """Exact P4(x)=F^{-1}(F(0) xor x*e_7), x=0,...,255.

    Its eight varying bytes are correlated; NEVER replace with eight
    independently active bytes. The rest of the state is identically zero.
    """
    zero=np.zeros(64,dtype=np.uint8)
    target=np.broadcast_to(F(zero),(N,64)).copy()
    target[:,INPUT_VARIABLE]^=np.arange(256,dtype=np.uint8)
    p=Finv(target)
    assert np.array_equal(F(p),target)
    assert set(np.where(np.any(p!=0,axis=0))[0].tolist())==set(WEAK_INDEX)
    assert np.all(p[:,OFFSET_BYTE]==0) and np.all(p[0]==0)
    assert np.unique(p,axis=0).shape[0]==N
    assert all(np.unique(p[:,i]).size==256 for i in WEAK_INDEX)
    p.flags.writeable=False
    return p


BASE_P4=inverse_defined_plaintexts()


def chosen_structures(rng):
    """Two disjoint valid backward multisets with safe offset a*e_1."""
    delta=int(rng.integers(1,256))
    p0=BASE_P4
    p1=p0.copy()
    p1[:,OFFSET_BYTE]^=np.uint8(delta)
    assert np.all(p1[:,OFFSET_BYTE]==delta)
    assert np.all(p0[:,OFFSET_BYTE]==0)
    return [p0,p1],delta


def restricted_subkeys(rng):
    """Synthetic Kalyna-512/512 subkeys satisfying exact Kpw restriction.

    Enforce odd-round RotateLeft_152 relations K1=Rot(K0), K3=Rot(K2),
    K5=Rot(K4). There is NO claim a master key expands to this tuple.
    """
    k=rng.integers(0,256,(6,64),dtype=np.uint8)
    k[0,list(WEAK_INDEX)]=0
    for r in (1,3,5):k[r]=odd_from_even(k[r-1])
    return k


def forward5(p,k):
    x0=add64(p,k[0])
    x1=F(x0)^k[1]
    x2=F(x1)^k[2]
    x3=F(x2)^k[3]
    x4=F(x3)^k[4]
    c=add64(F(x4),k[5])
    return [x0,x1,x2,x3,x4],c


def verify_integral(ps,k,delta):
    """Validate exact structure, 4R balance and 5R pointwise inversion."""
    assert k.shape==(6,64)
    if np.any(k[0,list(WEAK_INDEX)]):
        raise AssertionError('INVALID weak pre-whitening: one of eight K0 bytes is nonzero')
    for r in (1,3,5):
        if not np.array_equal(k[r],odd_from_even(k[r-1])):
            raise AssertionError(f'Wrong odd/even rotation K{r}')
    if not np.array_equal(even_from_odd(k[5]),k[4]):
        raise AssertionError('Algorithm 2 failed to derive K4 from K5')
    output=[]
    for which,p in enumerate(ps):
        assert p.shape==(N,64)
        assert np.all(p[:,OFFSET_BYTE]==(0 if which==0 else delta))
        assert np.unique(p,axis=0).shape[0]==N
        for i in range(64):
            n=np.unique(p[:,i]).size
            if n!=(256 if i in WEAK_INDEX else 1):
                raise AssertionError(('P4 support property failed',which,i,n))
        states,c=forward5(p,k)
        x0,x1,x2,x3,x4=states
        # This establishes that modular addition does NOT disturb the
        # key-dependent correlated input support, not merely bytewise All.
        pw_xor=x0^p
        if np.any(pw_xor[:,list(WEAK_INDEX)]):
            raise AssertionError('Carry contaminated a varying P4 byte')
        if not np.all(pw_xor==pw_xor[0]):
            raise AssertionError('The pre-whitening XOR translation depends on x')
        const=np.arange(64)!=7
        if not np.all(x1[:,const]==x1[0,const]):
            raise AssertionError('Round 1 must have one active byte at 7')
        if np.unique(x1[:,7]).size!=256:
            raise AssertionError('Round 1 single active byte fails to enumerate GF256')
        for byte in range(64):
            n2=np.unique(x2[:,byte]).size
            expected=256 if byte>=56 else 1
            if n2!=expected:raise AssertionError(('Round 2 A/C',byte,n2,expected))
            if np.unique(x3[:,byte]).size!=256:
                raise AssertionError(('Round 3 All',byte))
        if np.any(xorsum(x4)):
            raise AssertionError(('Round 4 balance failed',xorsum(x4).tolist()))
        if not np.array_equal(Finv(sub64(c,k[5])),x4):
            raise AssertionError('Incorrect pointwise 5R inversion')
        output.append((states,c))
    return output


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
    rng=np.random.default_rng(np.random.SeedSequence([int(seed),int(trial),5125125]))
    keys=restricted_subkeys(rng)
    ps,offset=chosen_structures(rng)
    data=verify_integral(ps,keys,offset)
    cts=[item[1] for item in data]
    correct=wrong_tested=first=both=0
    survivors=[]
    for j in range(8):
        real=keys[5,8*j:8*(j+1)]
        passed,sums=column_filter_exact(cts,j,real)
        if not passed:
            raise AssertionError(('Correct K5 column rejected',j,sums.tolist()))
        correct+=1
        test=make_wrong_keys(get_key_col_u64(keys[5],j),rng,trial,j,
                             random_wrong,single_bit_wrong,msb_differences,
                             trial<full_msb_trials)
        survive,f,n=guess_filter_fast(get_col_u64(cts,j),test)
        for g in survive:
            gb=np.frombuffer(int(g).to_bytes(8,'little'),dtype=np.uint8)
            direct,_=column_filter_exact(cts,j,gb)
            assert direct
            survivors.append(dict(trial=trial,column=j,wrong_candidate_hex=gb.tobytes().hex()))
        first+=f;both+=len(survive);wrong_tested+=n
    # Controls deliberately violate the source hypothesis and record the
    # *observed* failure. The theorem gives no converse, so do not claim
    # that every non-weak case MUST be unbalanced.
    control_total=0
    control_both_balanced=0
    if trial < nonweak_controls:
        for index in WEAK_INDEX:
            kbad=keys.copy()
            kbad[0,index]=np.uint8(1+((trial+index*17)%255))
            kbad[1]=odd_from_even(kbad[0])
            balance=[]
            for p in ps:
                s,_=forward5(p,kbad)
                balance.append(bool(not np.any(xorsum(s[-1]))))
            control_total+=1
            control_both_balanced+=int(all(balance))
    res=dict(trial=trial,seed=seed,synthetic_restricted_subkeys=True,
             master_key_expansion_compatibility='NOT ESTABLISHED',
             pre_whitening_condition='K0[i]=0 for i in {0,15,22,29,36,43,50,57}',
             weak_byte_positions=list(WEAK_INDEX),weak_bytes_zero=True,
             second_multiset_offset_byte1=offset,chosen_plaintexts=512,
             base_multiset_size=256,balanced_bytes_each=64,
             both_4round_distinguishers_pass=True,
             correct_K5_columns_retained=correct,
             true_K4_derived_from_K5=True,
             wrong_column_candidate_evaluations=wrong_tested,
             wrong_first_multiset_survivors=first,
             wrong_both_multiset_survivors=both,
             nonweak_controls_tested=control_total,
             nonweak_controls_balanced_both=control_both_balanced,
             full_msb_255_per_column=trial<full_msb_trials)
    vectors=None
    if trial==0:
        vectors=dict(weak_key_byte_indices=list(WEAK_INDEX),
             subkeys_K0_to_K5=[k.tobytes().hex() for k in keys],
             second_offset_byte1=offset,
             zero_prewhitening_bytes_verified=True,
             exact_backwards_definition='P4(x)=F^-1(F(0) XOR x*e_7)',
             synthetic_round_keys_not_master_expanded=True,
             correct_terminal_key_K5=keys[5].tobytes().hex(),
             derived_K4=even_from_odd(keys[5]).tobytes().hex(),
             row_specific_inverse_sr_sets=[list(q) for q in I_SETS],
             official_reference=verify_primitives(),two_multisets=[])
        for p,(states,c) in zip(ps,data):
            x0,x1,x2,x3,x4=states
            vectors['two_multisets'].append(dict(
                plaintext_set_sha256=hashlib.sha256(p.tobytes()).hexdigest(),
                ciphertext_set_sha256=hashlib.sha256(c.tobytes()).hexdigest(),
                first_plaintext=p[0].tobytes().hex(),
                last_plaintext=p[-1].tobytes().hex(),
                first_ciphertext=c[0].tobytes().hex(),
                last_ciphertext=c[-1].tobytes().hex(),
                first_X0=x0[0].tobytes().hex(),first_X1=x1[0].tobytes().hex(),
                first_X2=x2[0].tobytes().hex(),first_X3=x3[0].tobytes().hex(),
                first_X4=x4[0].tobytes().hex(),
                XOR_sum_X4=xorsum(x4).tobytes().hex(),
                XOR_sum_ciphertext=xorsum(c).tobytes().hex(),
                min_unique_count_X1=1,max_unique_count_X1=256))
    return res,survivors,vectors


def main():
    p=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument('--trials',type=int,default=1000)
    p.add_argument('--seed',type=int,default=20261117)
    p.add_argument('--jobs',type=int,default=4)
    p.add_argument('--random-wrong',type=int,default=4)
    p.add_argument('--single-bit-wrong',type=int,default=4)
    p.add_argument('--msb-differences',type=int,default=4)
    p.add_argument('--full-msb-trials',type=int,default=3)
    p.add_argument('--nonweak-controls',type=int,default=20,
                   help='First N trials: deliberately violate each of 8 Kpw zero bytes')
    p.add_argument('--progress-every',type=int,default=100)
    p.add_argument('--out',default='KALYNA512_512_R5_RESULTS')
    p.add_argument('--resume',action='store_true')
    args=p.parse_args()
    if args.trials<1 or args.jobs<1 or args.progress_every<1 or any(
        getattr(args,k)<0 for k in ('random_wrong','single_bit_wrong','msb_differences','full_msb_trials','nonweak_controls')):
        p.error('Invalid argument: negative sample counts or nonpositive trial/jobs/progress count')
    root=Path(args.out);root.mkdir(parents=True,exist_ok=True)
    computational={k:getattr(args,k) for k in ('trials','seed','random_wrong',
        'single_bit_wrong','msb_differences','full_msb_trials','nonweak_controls')}
    source_sha=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    cfg=root/'settings.json'
    if args.resume:
        if not cfg.exists():raise FileNotFoundError('No settings file for resume')
        previous=json.loads(cfg.read_text())
        if previous['args']!=computational or previous['source_sha256']!=source_sha:
            raise ValueError('Source/settings mismatch for resume')
    else:
        if cfg.exists():raise FileExistsError('Existing run; use --resume')
        cfg.write_text(json.dumps(dict(args=computational,source_sha256=source_sha,
            version=VERSION,python=sys.version,numpy=np.__version__,host=platform.platform(),
            reference=REFERENCE,reference_commit=REFERENCE_COMMIT),indent=2))
    known=verify_primitives()
    (root/'official_known_answer.json').write_text(json.dumps(known,indent=2))
    records={}
    if args.resume and (root/'trials.jsonl').exists():
        for line in (root/'trials.jsonl').read_text().splitlines():
            if line.strip():
                x=json.loads(line)
                if x['trial'] in records:raise AssertionError('Duplicate trial record')
                records[x['trial']]=x
    missing=[t for t in range(args.trials) if t not in records]
    t0=time.perf_counter()
    print('Kalyna-512/512: weak-prewhitening 4R integral + 5R Algorithm 2 filter',flush=True)
    print('REQUIRED K0 zero bytes:',WEAK_INDEX,flush=True)
    print('Pre-whitening is retained! Synthetic restricted subkeys; not master-expanded.',flush=True)
    print('P4=Finv(F(0) XOR x*e7); second valid multiset P4 XOR a*e1, a !=0',flush=True)
    print('Official full cipher encryption/decryption reference vectors: PASS',flush=True)
    print(f'Target {args.trials}; missing {len(missing)}; 2x256 texts; 8 columns',flush=True)
    def save(result):
        d,surv,vectors=result
        if d['trial'] in records:raise AssertionError('Duplicate trial')
        records[d['trial']]=d
        with (root/'trials.jsonl').open('a') as f:f.write(json.dumps(d,sort_keys=True)+'\n')
        if surv:
            with (root/'wrong_key_survivors.jsonl').open('a') as f:
                for r in surv:f.write(json.dumps(r,sort_keys=True)+'\n')
        if vectors is not None:
            (root/'reproducible_test_vectors.json').write_text(json.dumps(vectors,indent=2))
        n=len(records)
        if n%args.progress_every==0 or n==args.trials:
            print(f'Progress {n}/{args.trials}: balanced {2*n}/{2*args.trials}; correct K5 columns {sum(x["correct_K5_columns_retained"] for x in records.values())}/{8*n}; wrong guesses {sum(x["wrong_column_candidate_evaluations"] for x in records.values())}; wrong survivors {sum(x["wrong_both_multiset_survivors"] for x in records.values())}; elapsed {time.perf_counter()-t0:.2f}s',flush=True)
    if args.jobs==1:
        for t in missing:
            save(run_trial(t,args.seed,args.random_wrong,args.single_bit_wrong,
                          args.msb_differences,args.full_msb_trials,args.nonweak_controls))
    else:
        with ProcessPoolExecutor(max_workers=args.jobs) as exe:
            futures={exe.submit(run_trial,t,args.seed,args.random_wrong,args.single_bit_wrong,
                          args.msb_differences,args.full_msb_trials,args.nonweak_controls):t for t in missing}
            for f in as_completed(futures):save(f.result())
    rows=[records[i] for i in range(args.trials)]
    if not all(x['both_4round_distinguishers_pass'] and x['weak_bytes_zero'] and
               x['correct_K5_columns_retained']==8 and x['true_K4_derived_from_K5'] for x in rows):
        raise AssertionError('Positive test failed')
    cols=['trial','seed','chosen_plaintexts','both_4round_distinguishers_pass',
          'weak_bytes_zero','second_multiset_offset_byte1','balanced_bytes_each',
          'correct_K5_columns_retained','true_K4_derived_from_K5',
          'wrong_column_candidate_evaluations','wrong_first_multiset_survivors',
          'wrong_both_multiset_survivors','nonweak_controls_tested',
          'nonweak_controls_balanced_both','full_msb_255_per_column']
    with (root/'trial_summary.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=cols);writer.writeheader()
        for d in rows:writer.writerow({k:d[k] for k in cols})
    summary=dict(
        variant='Kalyna-512/512',target_rounds=5,integral_rounds=4,
        positive_trials=args.trials,complete_multisets=2*args.trials,
        chosen_plaintexts_per_trial=512,balanced_internal_bytes_per_multiset=64,
        valid_distinguisher_trials=sum(x['both_4round_distinguishers_pass'] for x in rows),
        correct_K5_column_candidates_retained=sum(x['correct_K5_columns_retained'] for x in rows),
        correct_K5_column_candidates_expected=8*args.trials,
        correct_K4_derived_from_K5=sum(x['true_K4_derived_from_K5'] for x in rows),
        wrong_64bit_column_evaluations=sum(x['wrong_column_candidate_evaluations'] for x in rows),
        wrong_64bit_column_candidates_surviving_first=sum(x['wrong_first_multiset_survivors'] for x in rows),
        wrong_64bit_column_candidates_surviving_both=sum(x['wrong_both_multiset_survivors'] for x in rows),
        deliberately_nonweak_controls=sum(x['nonweak_controls_tested'] for x in rows),
        nonweak_controls_passing_both=sum(x['nonweak_controls_balanced_both'] for x in rows),
        full_msb_exhaustive_byte_trials=sum(x['full_msb_255_per_column'] for x in rows),
        weak_prewhitening_zero_byte_indices=list(WEAK_INDEX),
        admissible_prewhitening_subkey_fraction='2^-64',
        prewhitening_operation='64-bit column modular addition PRESENT',
        key_model='synthetic restricted subkeys with exact odd/even rotations',
        genuine_master_key_schedule_compatibility='NOT ESTABLISHED',
        key_search_exhaustive=False,unique_survivor_claim=False,master_key_recovery_claim=False,
        nominal_work='2^76 64-bit column partial-decryption operations, NOT full encryptions',
        elapsed_current_session_seconds=round(time.perf_counter()-t0,3))
    (root/'summary.json').write_text(json.dumps(summary,indent=2))
    report='''# Kalyna-512/512: conditional four-round integral and five-round filtering\n\n'''
    report+='\n'.join(f'- **{k}**: {v}' for k,v in summary.items())
    report+='''\n\n## Exact hypothesis (updated paper Section 5.2, Table 2)\n\nThe initial pre-whitening is **present**: 64-bit modular addition in each of eight columns. Its 512-bit subkey K0 has the eight mandatory zero bytes at byte indices I={0,15,22,29,36,43,50,57}. The remaining 56 bytes are arbitrary. The fraction among possible 512-bit *pre-whitening subkeys* is 2^-64, and is **not** a demonstrated fraction among expanded 512-bit master keys.\n\nChoose P4(x) = F^-1(F(0) XOR x*e7) for x=0,...,255. Exactly eight plaintext bytes vary (the same I) and they are **correlated functions of the one common x**, not independently chosen variables. The second multiset is P4(x) XOR a*e1 with nonzero fixed a; e1 is a safe offset above the variable byte 0 in the first 64-bit column. Both input sets consist of 256 distinct elements and are disjoint. Under the zero-byte restriction, pre-whitening acts as an x-independent XOR translation, including all carry effects.\n\nAfter round 1, a single byte at position 7 is All; after round 2, the last column has eight All bytes; after round 3, all 64 bytes are All; after round 4, all 64 bytes are Balanced. These properties are checked pointwise on complete input multisets. The balanced state is X4, **before** fifth-round F and modular terminal addition: C = F(X4) boxplus K5. It is wrong to test the ciphertext for the integral balance.\n\nAlgorithm 1 tests each guessed 64-bit column of terminal K5 by subtraction with exact borrows, inverse MC and inverse row-dependent S-box, with inverse ShiftRows recorded as eight complete input-index sets. Algorithm 2 derives the corresponding K4 = RotateRight_152(K5) on the **entire 512-bit subkey**, not each 64-bit column separately. K1=RotL_152(K0), K3=RotL_152(K2), K5=RotL_152(K4) are enforced on all six synthetic subkeys.\n\nThe experiment validates correct-candidate retention and sampled wrong-key rejection. Wrong candidate test families include random 64-bit guesses, single-bit changes, MSB differences, carry-boundary changes, and complete 255 MSB alternatives in the configured initial trials. Distinct surviving candidates, if any, are preserved. This is **not exhaustive 2^64** search, not proof of a unique solution, and **not a recovery of a genuine master key**. The synthetic round keys have not been shown to arise from an actual Kalyna master-key expansion.\n\n## Reference implementation\n\nThe official full-cipher 512/512 encryption and decryption known-answer vectors are checked at startup. Authors' repository: https://github.com/Roman-Oliynykov/Kalyna-reference ; pinned commit `22eafbcaf6635dc5e1f8a734b1f7c5ab84b5a5ea`.\n'''
    (root/'REPORT.md').write_text(report)
    print('COMPLETE '+json.dumps(summary,sort_keys=True),flush=True)
    return 0


if __name__=='__main__':
    raise SystemExit(main())
