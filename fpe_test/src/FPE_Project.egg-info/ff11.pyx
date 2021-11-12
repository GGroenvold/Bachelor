# Ceil function
import math
#from utils import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from enum import Enum, auto
from re import sub
from libc.string cimport memcpy 
from libc.stdlib cimport malloc
import time
from format_translator import *

start_time = time.time()


T = bytes.fromhex('3737373770717273373737')
key = bytes.fromhex('2B7E151628AED2A6ABF7158809CF4F3C')
cipher = AES.new(key, AES.MODE_ECB)

cdef int num_radix(radix, int* numbers):
    cdef int x = 0
    cdef int i = 0
    cdef int length = sizeof(numbers)/sizeof(int)
    for i in range(length):
        x = x * radix + numbers[i]
    return x

cdef int* str_radix(radix, length, number):
    if length < 1:
        raise ValueError(f"{length} is not a valid string length")

    if not (0 <= number <= radix ** length):
        raise ValueError(f"{number} is not in range [0;{radix}^{length}]")

    cdef int* numerals = <int *> malloc(length*sizeof(int))

    for i in range(length):
        numerals[length - 1 - i] = number % radix
        number = number // radix
    return numerals

def PRF(X,cipher):
    cdef int m = len(X)/16
    Yj = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    cdef int j
    for j in range(m):
        Xj = X[j * 16:(j * 16) + 16]
        Yj = cipher.encrypt(bytes(A ^ B for A, B in zip(Yj, Xj)))
    return Yj


cdef int* encrypt_main(int* msg, T, key, radix,cipher):
    cdef int t = len(T)
    cdef int n = sizeof(msg)/sizeof(char)

    cdef int u = n // 2
    cdef int v = n - u
    cdef int *A = <int *> malloc(u*sizeof(int))
    cdef int *B = <int *> malloc(v*sizeof(int))
    cdef int *C = <int *> malloc(v*sizeof(int))
    memcpy(A, msg, u*sizeof(int))
    memcpy(B, msg+u, v*sizeof(int))
    cdef int b = math.ceil(math.ceil(v * math.log2(radix)) / 8)
    cdef int d = 4 * math.ceil(b / 4) + 4
    P = b'\x01' + b'\x02' + b'\x01' + \
        radix.to_bytes(3, 'big') + b'\n' + \
        (u % 256).to_bytes(1, 'big') + \
        n.to_bytes(4, 'big') + t.to_bytes(4, 'big')
    i = 0
    for i in range(10):
        Q = T + (0).to_bytes((-t - b - 1) % 16, 'big') + (i).to_bytes(1, 'big') + num_radix(radix, B).to_bytes(b, 'big')
        R = PRF(P + Q,cipher)
        S = R
        for j in range(1, int(math.ceil(d / 16))):
            S = S + cipher.encrypt(bytes(A ^ B for A, B in zip(R, (j).to_bytes(16, 'big'))))
        S = S[:d]
        y = int.from_bytes(S, 'big')
        if (i % 2 == 0):
            m = u
        else:
            m = v
        c = (num_radix(radix, A) + y) % radix ** m 
        C = str_radix(radix, m, c)
        A = B
        B = C
    
    cdef int *SUM = <int *> malloc(n*sizeof(int))
    memcpy(SUM, A, u*sizeof(int))
    memcpy(SUM+u, B, v*sizeof(int))

    return (SUM)

cdef int* decrypt_main(int* msg, T, key, radix,cipher):
    cdef int t = len(T)
    cdef int n = sizeof(msg)/sizeof(char)

    cdef int u = n // 2
    cdef int v = n - u
    cdef int *A = <int *> malloc(u*sizeof(int))
    cdef int *B = <int *> malloc(v*sizeof(int))
    cdef int *C = <int *> malloc(u*sizeof(int))
    memcpy(A, msg, u*sizeof(int))
    memcpy(B, msg+u, v*sizeof(int))
    cdef int b = math.ceil(math.ceil(v * math.log2(radix)) / 8)
    cdef int d = 4 * math.ceil(b / 4) + 4
    P = b'\x01' + b'\x02' + b'\x01' + \
        radix.to_bytes(3, 'big') + b'\n' + \
        (u % 256).to_bytes(1, 'big') + \
        n.to_bytes(4, 'big') + t.to_bytes(4, 'big')
    i = 0
    for i in range(10):
        Q = T + (0).to_bytes((-t - b - 1) % 16, 'big') + (i).to_bytes(1, 'big') + num_radix(radix, A).to_bytes(b, 'big')
        R = PRF(P + Q,cipher)
        S = R
        for j in range(1, int(math.ceil(d / 16))):
            S = S + cipher.encrypt(bytes(A ^ B for A, B in zip(R, (j).to_bytes(16, 'big'))))
        S = S[:d]
        y = int.from_bytes(S, 'big')
        if (i % 2 == 0):
            m = u
        else:
            m = v
        c = (num_radix(radix, B) - y) % radix ** m 
        C = str_radix(radix, m, c)
        B = A
        A = C
    
    cdef int *SUM = <int *> malloc(n*sizeof(int))
    memcpy(SUM, A, u*sizeof(int))
    memcpy(SUM+u, B, v*sizeof(int))

    return (SUM)


cdef int * encrypt(msg, T, key, format):
    cipher = AES.new(key, AES.MODE_ECB)

    cdef int plainNumerals[5]
    cdef int* cipherNumerals

    radix = 58
    plainNumerals = {7,4,11,11,14}
    cipherNumerals = encrypt_main(plainNumerals, T, key, radix,cipher)

    return cipherNumerals

cdef int * ciphertext

ciphertext = encrypt('hellos', T, key, Format.LETTERS)

for i in range(5):
    printf("%d", ciphertext[i])