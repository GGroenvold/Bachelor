# Ceil function
import math
#from utils import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from enum import Enum, auto
from libc.stdlib cimport malloc, free
from libc.string cimport memcpy
from libc.string cimport strcpy, strlen
import cython

#from format_translator import *

cdef int num_radix(int radix, int* numbers, int length):
    cdef int x = 0
    cdef int i = 0
    for i in range(length):
        x = x * radix + numbers[i]
    return x

cdef int* str_radix(int radix, int length, int number):
    if length < 1:
        raise ValueError(f"{length} is not a valid string length")

    if not (0 <= number <= radix ** length):
        raise ValueError(f"{number} is not in range [0;{radix}^{length}]")

    cdef int* numerals = <int *> malloc(length*sizeof(int))

    cdef int i

    for i in range(length):
        numerals[length - 1 - i] = number % radix
        number = number / radix
    return numerals

cdef bytes xor16ByteArray(bytes A, bytes B):
    
    cdef unsigned char* Ac = <unsigned char *> malloc(16*sizeof(char))
    cdef unsigned char* Bc = <unsigned char *> malloc(16*sizeof(char))
    cdef unsigned char* xor = <unsigned char *> malloc(16*sizeof(char))
    cdef int i
    for i in range(16):
        Ac[i] = A[i]
        Bc[i] = B[i]
        xor[i] = (Ac[i] ^ Bc[i])

    cdef bytes result = xor[:16]

    return result

cdef bytes PRF(bytes X,cipher):
    cdef int m = len(X)/16
    cdef bytes Yj = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    cdef int j
    cdef bytes Xj
    for j in range(m):
        Xj = X[j * 16:(j * 16) + 16]
        Yj = cipher.encrypt(xor16ByteArray(Xj,Yj))
    return Yj


cdef list encrypt_main(list msg, bytes T, bytes key, int radix, cipher):
    cdef int n = len(msg)
    cdef t = len(T)
    cdef int u = n / 2
    cdef int v = n - u
    cdef int j
    cdef int c
    cdef int m = v
    cdef int l
    cdef int i
    cdef int g 

    cdef int * plainNumerals = <int *> malloc(n*sizeof(int))

    for g in range(n):
        plainNumerals[g] = msg[g]

    cdef int *A = <int *> malloc(u*sizeof(int))
    cdef int *B = <int *> malloc(v*sizeof(int))
    cdef int *C = <int *> malloc(v*sizeof(int))

    memcpy(A, plainNumerals, u*sizeof(int))
    memcpy(B, plainNumerals+u, v*sizeof(int))

    cdef int b = math.ceil(math.ceil(v * math.log2(radix)) / 8)
    cdef int d = 4 * math.ceil(b / 4.0) + 4
    cdef int k = math.ceil(d/16.0)

    cdef bytes P = b'\x01' + b'\x02' + b'\x01' + \
        radix.to_bytes(3, 'big') + b'\n' + \
        (u % 256).to_bytes(1, 'big') + \
        n.to_bytes(4, 'big') + t.to_bytes(4, 'big')

    cdef bytes Q
    cdef bytes R
    
    for i in range(10):
        Q = T + (0).to_bytes((-t - b - 1) % 16, 'big') + (i).to_bytes(1, 'big') + num_radix(radix, B, m).to_bytes(b, 'big')
        R = PRF(P + Q,cipher)
        S = R
        for j in range(1, k):
            S = S + cipher.encrypt(bytes(A ^ B for A, B in zip(R, (j).to_bytes(16, 'big'))))
        S = S[:d]
        y = int.from_bytes(S, 'big')
        if (i % 2 == 0):
            m = u
            l = v
        else:
            m = v
            l = u
        c = (num_radix(radix, A, m) + y) % radix ** m
        C = str_radix(radix, m, c)
        memcpy(A, B, l*sizeof(int))
        memcpy(B, C, m*sizeof(int))
    
    cdef int *SUM = <int *> malloc(n*sizeof(int))
    memcpy(SUM, A, u*sizeof(int))
    memcpy(SUM+u, B, v*sizeof(int))

    cipherNumerals = [value for value in SUM[:n]]

    return cipherNumerals

cdef list decrypt_main(list msg, bytes T, bytes key, int radix, cipher):
    cdef int n = len(msg)
    cdef t = len(T)
    cdef int u = n / 2
    cdef int v = n - u
    cdef int j
    cdef int c
    cdef int m = u
    cdef int l
    cdef int i

    cdef int * plainNumerals = <int *> malloc(n*sizeof(int))

    for g in range(n):
        plainNumerals[g] = msg[g]

    cdef int *A = <int *> malloc(u*sizeof(int))
    cdef int *B = <int *> malloc(v*sizeof(int))
    cdef int *C = <int *> malloc(v*sizeof(int))
    
    memcpy(A, plainNumerals, u*sizeof(int))
    memcpy(B, plainNumerals+u, v*sizeof(int))

    cdef int b = math.ceil(math.ceil(v * math.log2(radix)) / 8)
    cdef int d = 4 * math.ceil(b / 4.0) + 4
    cdef int k = math.ceil(d/16.0)

    cdef bytes P = b'\x01' + b'\x02' + b'\x01' + \
        radix.to_bytes(3, 'big') + b'\n' + \
        (u % 256).to_bytes(1, 'big') + \
        n.to_bytes(4, 'big') + t.to_bytes(4, 'big')

    cdef bytes Q
    cdef bytes R

    for i in range(9, -1, -1):
        Q = T + (0).to_bytes((-t - b - 1) % 16, 'big') + (i).to_bytes(1, 'big') + num_radix(radix, A, m).to_bytes(b, 'big')
        R = PRF(P + Q,cipher)
        S = R
        for j in range(1, k):
            S = S + cipher.encrypt(bytes(A ^ B for A, B in zip(R, (j).to_bytes(16, 'big'))))
        S = S[:d]
        y = int.from_bytes(S, 'big')
        if (i % 2 == 0):
            m = u
            l = v
        else:
            m = v
            l = u
        c = (num_radix(radix, B, m) - y) % radix ** m 
        C = str_radix(radix, m, c)
        memcpy(B, A, l*sizeof(int))
        memcpy(A, C, m*sizeof(int))
    
    cdef int *SUM = <int *> malloc(4*sizeof(int))
    memcpy(SUM, A, u*sizeof(int))
    memcpy(SUM+u, B, v*sizeof(int))

    cipherNumerals = [value for value in SUM[:n]]

    return cipherNumerals

cpdef list encrypt(list msg, bytes T, bytes key, int radix, cipher):

    cipherNumerals = encrypt_main(msg, T, key, radix, cipher)

    return cipherNumerals

cpdef list decrypt(list msg, bytes T, bytes key, int radix, cipher):

    plainNumerals = decrypt_main(msg, T, key, radix, cipher)

    return plainNumerals
