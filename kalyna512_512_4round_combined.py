#!/usr/bin/env python3
"""Kalyna-512/512: key-independent 3-round integral + 4-round filtering.

Standalone research validation based on updated manuscript Sec. 5.1/Table 2.
State: 8 x 8 bytes, column-major, little-endian 64-bit words.
K0 is modular pre-whitening (NO weak-key restriction). K1..K3 XOR at the
ends of internal rounds. K4 is terminal modular addition. The balanced
state is X3 BEFORE terminal modular addition, not the ciphertext.

The 2^64 key-column search is NOT exhaustive, and no master-key recovery
is claimed. Two complete, distinct 256-plaintext structures per trial.
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

VERSION = '1.0-512'
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


def chosen_structures(rng):
    # Active MSB of column 0 (byte 7), and two disjoint offsets at byte 4.
    base=rng.integers(0,256,64,dtype=np.uint8)
    base[7]=0
    p0=np.broadcast_to(base,(256,64)).copy()
    p0[:,7]=np.arange(256,dtype=np.uint8)
    p1=p0.copy()
    delta=int(rng.integers(1,256))
    p1[:,4]^=np.uint8(delta)
    return [p0,p1],delta


def states_3round(plaintext,keys):
    x0=add64(plaintext,keys[0])
    x1=F(x0)^keys[1]
    x2=F(x1)^keys[2]
    x3=F(x2)^keys[3]
    return [x0,x1,x2,x3]


def encrypt_4round(plaintext,keys):
    return add64(F(states_3round(plaintext,keys)[-1]),keys[4])


def verify_distinguisher(ps,keys):
    assert len(ps)==2 and all(p.shape==(256,64) for p in ps)
    if int(ps[0][0,4])==int(ps[1][0,4]):
        raise AssertionError('Multisets overlap')
    states=[]
    for p in ps:
        if np.unique(p[:,7]).size!=256:
            raise AssertionError('Active byte does not span all 256 values')
        if np.any(p[:,np.arange(64)!=7]!=p[0,np.arange(64)!=7]):
            raise AssertionError('Extra plaintext activity')
        x0,x1,x2,x3=states_3round(p,keys)
        # A/C after MODULAR prewhitening and first round; constant carry into MSB.
        if np.unique(x0[:,7]).size!=256:
            raise AssertionError('Pre-whitening lost active byte')
        if not np.all(x0[:,np.arange(64)!=7]==x0[0,np.arange(64)!=7]):
            raise AssertionError('Spurious active byte under prewhitening')
        for byte in range(64):
            expected_unique=256 if byte in range(56,64) else 1
            if np.unique(x1[:,byte]).size!=expected_unique:
                raise AssertionError(('Round 1 A/C mismatch',byte))
            if np.unique(x2[:,byte]).size!=256:
                raise AssertionError(('Round 2 A property mismatch',byte))
        if np.any(xorsum(x3)):
            raise AssertionError(('Round 3 not balanced',xorsum(x3).tolist()))
        states.append([x0,x1,x2,x3])
    return states


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


def run_trial(trial,seed,random_wrong,single_bit_wrong,msb_differences,full_msb_trials):
    rng=np.random.default_rng(np.random.SeedSequence([int(seed),int(trial),5125124]))
    master=rng.integers(0,256,64,dtype=np.uint8)
    keys=expand_key(master)
    if not np.array_equal(keys[3],odd_from_even(keys[2])):
        raise AssertionError('Invalid genuine subkey expansion')
    ps,offset=chosen_structures(rng)
    x_states=verify_distinguisher(ps,keys)
    cts=[add64(F(ss[-1]),keys[4]) for ss in x_states]
    for c,states in zip(cts,x_states):
        if not np.array_equal(Finv(sub64(c,keys[4])),states[-1]):
            raise AssertionError('Incorrect pointwise 4R inversion')
    correct=0; wrong_tested=0; first=0; both=0; survivor_rows=[]
    full_msb=trial<full_msb_trials
    for j in range(8):
        true_col=keys[4,8*j:8*(j+1)]
        valid,sums=column_filter_exact(cts,j,true_col)
        if not valid:raise AssertionError(('Correct K4 column rejected',j,sums.tolist()))
        correct+=1
        u=get_col_u64(cts,j)
        cand=make_wrong_keys(get_key_col_u64(keys[4],j),rng,trial,j,
                             random_wrong,single_bit_wrong,msb_differences,full_msb)
        survived,f,n=guess_filter_fast(u,cand)
        # Confirm exactly that all retained candidate columns satisfy direct check.
        for g in survived:
            gg=np.frombuffer(int(g).to_bytes(8,'little'),dtype=np.uint8)
            passed,actual=column_filter_exact(cts,j,gg)
            assert passed and np.all(actual==0)
            survivor_rows.append(dict(trial=trial,column=j,wrong_candidate=int(g).to_bytes(8,'little').hex()))
        wrong_tested+=n;first+=f;both+=len(survived)
    result=dict(trial=trial,seed=seed,master_key_hex=master.tobytes().hex(),
                chosen_plaintexts=512,active_byte_position=7,second_structure_offset_byte4=offset,
                pw_condition='arbitrary genuine K0; no weak-key requirement',
                both_distinguisher_multisets_pass=True,balanced_bytes_per_multiset=64,
                genuine_key_schedule=True,correct_K4_columns_retained=correct,
                wrong_column_candidate_evaluations=wrong_tested,
                wrong_first_multiset_survivors=first,wrong_both_multiset_survivors=both,
                full_msb_255_per_column=full_msb)
    if trial==0:
        vectors=dict(master_key_hex=master.tobytes().hex(),
                     round_subkeys_0_to_4=[k.tobytes().hex() for k in keys[:5]],
                     active_byte=7,second_offset_byte4=offset,
                     column_inverse_shiftrows_input_sets=[list(s) for s in I_SETS],
                     known_answer_test=verify_primitives(),two_multisets=[])
        for p,c,st in zip(ps,cts,x_states):
            vectors['two_multisets'].append(dict(
              first_plaintext=p[0].tobytes().hex(),last_plaintext=p[-1].tobytes().hex(),
              first_ciphertext=c[0].tobytes().hex(),
              first_X0=st[0][0].tobytes().hex(),first_X1=st[1][0].tobytes().hex(),
              first_X2=st[2][0].tobytes().hex(),first_X3=st[3][0].tobytes().hex(),
              XOR_sum_X3=xorsum(st[3]).tobytes().hex(),
              XOR_sum_ciphertext=xorsum(c).tobytes().hex()))
    else:vectors=None
    return result,survivor_rows,vectors


def main():
    p=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument('--trials',type=int,default=1000)
    p.add_argument('--seed',type=int,default=20261117)
    p.add_argument('--jobs',type=int,default=4)
    p.add_argument('--random-wrong',type=int,default=4)
    p.add_argument('--single-bit-wrong',type=int,default=4)
    p.add_argument('--msb-differences',type=int,default=4)
    p.add_argument('--full-msb-trials',type=int,default=3)
    p.add_argument('--progress-every',type=int,default=100)
    p.add_argument('--out',default='KALYNA512_512_R4_RESULTS')
    p.add_argument('--resume',action='store_true')
    args=p.parse_args()
    if args.trials<1 or args.jobs<1 or args.progress_every<1 or args.full_msb_trials<0:
        p.error('Invalid trials/jobs/progress/full-msb-trials')
    out=Path(args.out);out.mkdir(parents=True,exist_ok=True)
    run_args={k:getattr(args,k) for k in ('trials','seed','random_wrong','single_bit_wrong',
                                           'msb_differences','full_msb_trials')}
    source_sha=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    cfg=out/'settings.json'
    if args.resume:
        if not cfg.exists():raise FileNotFoundError('No settings file found for resume')
        old=json.loads(cfg.read_text())
        if old['args']!=run_args or old['source_sha256']!=source_sha:
            raise ValueError('Resume source or settings mismatch')
    else:
        if cfg.exists():raise FileExistsError('Output already configured; use --resume')
        cfg.write_text(json.dumps(dict(args=run_args,source_sha256=source_sha,
                       version=VERSION,python=sys.version,numpy=np.__version__,
                       host=platform.platform(),reference=REFERENCE,
                       reference_commit=REFERENCE_COMMIT),indent=2))
    known=verify_primitives()
    (out/'official_known_answer.json').write_text(json.dumps(known,indent=2))
    records={}
    if args.resume:
        for line in (out/'trials.jsonl').read_text().splitlines() if (out/'trials.jsonl').exists() else []:
            if line.strip():
                d=json.loads(line);records[d['trial']]=d
    missing=[t for t in range(args.trials) if t not in records]
    t0=time.perf_counter()
    print('Kalyna-512/512: key-independent 3R integral + 4R key-column filtering',flush=True)
    print('Official encryption/decryption known-answer tests: PASS',flush=True)
    print(f'Target {args.trials} trials; remaining {len(missing)}; 2x256 texts; 8 columns',flush=True)
    print('All 64 bytes after 3 internal rounds balanced; NO WEAK KEY condition',flush=True)
    print(f'Inverse-SR column input index sets: {I_SETS}',flush=True)
    def save(result):
        d,survivors,vectors=result
        if d['trial'] in records:return
        records[d['trial']]=d
        with (out/'trials.jsonl').open('a') as f:f.write(json.dumps(d,sort_keys=True)+'\n')
        if survivors:
            with (out/'wrong_key_survivors.jsonl').open('a') as f:
                for row in survivors:f.write(json.dumps(row,sort_keys=True)+'\n')
        if vectors is not None:
            (out/'reproducible_test_vectors.json').write_text(json.dumps(vectors,indent=2))
        n=len(records)
        if n%args.progress_every==0 or n==args.trials:
            print(f'Progress {n}/{args.trials}: correct columns {sum(x["correct_K4_columns_retained"] for x in records.values())}/{8*n}; wrong tested {sum(x["wrong_column_candidate_evaluations"] for x in records.values())}; wrong survive {sum(x["wrong_both_multiset_survivors"] for x in records.values())}; elapsed {time.perf_counter()-t0:.1f}s',flush=True)
    if args.jobs==1:
        for t in missing:
            save(run_trial(t,args.seed,args.random_wrong,args.single_bit_wrong,
                           args.msb_differences,args.full_msb_trials))
    else:
        with ProcessPoolExecutor(max_workers=args.jobs) as exe:
            fut={exe.submit(run_trial,t,args.seed,args.random_wrong,args.single_bit_wrong,
                            args.msb_differences,args.full_msb_trials):t for t in missing}
            for f in as_completed(fut):save(f.result())
    rows=[records[i] for i in range(args.trials)]
    if not all(d['both_distinguisher_multisets_pass'] and d['correct_K4_columns_retained']==8 for d in rows):
        raise AssertionError('Positive distinguisher or key filter failure')
    names=['trial','seed','chosen_plaintexts','both_distinguisher_multisets_pass',
           'balanced_bytes_per_multiset','correct_K4_columns_retained','genuine_key_schedule',
           'wrong_column_candidate_evaluations','wrong_first_multiset_survivors',
           'wrong_both_multiset_survivors','second_structure_offset_byte4',
           'full_msb_255_per_column']
    with (out/'trial_summary.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=names);w.writeheader()
        for d in rows:w.writerow({k:d[k] for k in names})
    summary=dict(trials=args.trials,valid_multisets=2*args.trials,
                 distinguisher_passed=sum(x['both_distinguisher_multisets_pass'] for x in rows),
                 balanced_bytes_each=64,chosen_plaintexts_per_trial=512,
                 correct_K4_columns_retained=sum(x['correct_K4_columns_retained'] for x in rows),
                 correct_K4_columns_expected=8*args.trials,
                 wrong_column_candidates_tested=sum(x['wrong_column_candidate_evaluations'] for x in rows),
                 wrong_candidates_passing_first=sum(x['wrong_first_multiset_survivors'] for x in rows),
                 wrong_candidates_passing_both=sum(x['wrong_both_multiset_survivors'] for x in rows),
                 genuine_master_keys=True,weak_key_restrictions='NONE',
                 full_msb_trials=sum(x['full_msb_255_per_column'] for x in rows),
                 full_master_key_recovered=False,exhaustive_key_search_performed=False,
                 nominal_column_operations='2^76 = 8 columns x 2^64 64-bit guesses x 2^9 texts',
                 nominal_cost_unit='64-bit column partial decryptions, NOT full encryptions',
                 elapsed_seconds_current_session=round(time.perf_counter()-t0,3))
    (out/'summary.json').write_text(json.dumps(summary,indent=2))
    report='# Kalyna-512/512: 3-round integral and 4-round key filtering\n\n'
    report+='\n'.join(f'- **{k}**: {v}' for k,v in summary.items())
    report+='''\n\n## Conditions, construction and scope\n\nUpdated paper: Sec. 5.1, Table 2, Algorithm 1.\nEach of two complete 256-text structures has byte 7 uniformly active and 63\nconstant bytes; they are disjoint due to a fixed nonzero offset at byte 4.\nGenuine 512-bit master keys and the exact full 512/512 master-key schedule.\nNo weak-key or no-prewhitening assumptions. Prewhitening adds K0 modulo 2^64\nper column. MSB-only activity survives with a constant carry.\n\nAfter round 1, eight All bytes occupy column 7. After round 2, all 64\nbytes are All (each can depend on the same active input variable). After\nround 3, all 64 internal bytes have XOR sum zero. This is checked BEFORE\nround 4 and its terminal modular addition. C = F(X3) boxplus K4.\n\nAlgorithm 1 independently guesses each 64-bit column of K4, subtracts it\nmodulo 2^64 with exact borrow, inverses MDS, inverses the row-dependent\nS-box and tests the eight byte-XOR sums across TWO multisets. Inverse\nShiftRows only permutes byte labels according to the recorded I_j sets.\nBecause K4 is EVEN, K3 is NOT rotated directly from K4; the genuine\nschedule does satisfy K3 = RotateLeft_152(K2).\n\nIncorrect guesses are explicitly sampled (random/bit/MSB/carry). The\nfast rejection algorithm computes the same predicate as the full direct\ncolumn inverse, and correct-key retention is checked by the direct inverse.\nNo exhaustive 2^64 search, uniqueness proof or master-key recovery is\nclaimed. Wrong guesses that pass either multiset are counted separately.\n'''
    (out/'REPORT.md').write_text(report)
    print('COMPLETE '+json.dumps(summary,sort_keys=True),flush=True)
    return 0

if __name__=='__main__':
    raise SystemExit(main())
