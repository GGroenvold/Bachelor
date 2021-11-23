from math import ceil, log
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from libc.stdlib cimport malloc, free
from libc.string cimport memcpy
import cython

# Constants
MIN_LEN = 2
TWEAK_LEN = 7

def reverse(string):
    return string[::-1]

def max_len(radix):
    return 2 * int(log(2**96, radix))

cdef num_radix(radix, int* numbers, int length):
    x = 0
    cdef int i = 0
    for i in range(length):
        x = x * radix + numbers[i]
    return x

cdef int* str_radix(radix, int length, number):
    if length < 1:
        raise ValueError(f"{length} is not a valid string length")

    if not (0 <= number <= radix ** length):
        raise ValueError(f"{number} is not in range [0;{radix}^{length}]")

    cdef int* numerals = <int *> malloc(length*sizeof(int))

    if not numerals:
        raise MemoryError()

    cdef int i

    for i in range(length):
        numerals[length - 1 - i] = number % radix
        number = number // radix
    return numerals


cdef int* reverseArray(int* arr, length):
    cdef int* numerals = <int *> malloc(length*sizeof(int))

    memcpy(numerals, arr, length*sizeof(int))

    cdef int i
    cdef int temp
    for i in range(length/2):
        temp = numerals[i];
        numerals[i] = numerals[length - 1 - i];
        numerals[length - 1 - i] = temp;

    return numerals

cdef bytes xorByteArray(unsigned char* A, unsigned char* B, int length):
    cdef unsigned char* xor = <unsigned char *> malloc(length*sizeof(char))

    if not xor:
        raise MemoryError()

    cdef int i
    for i in range(length):
        xor[i] = (A[i] ^ B[i])
        

    cdef bytes result = xor[:length]

    return result


cdef list encrypt_numeral_string(plainNumerals, T, radix, cipher):
    """
    Encrypt plaintext with FF3-1 cipher
    :param tweak: 56 bit
    :param numeral_string: numeral string with length n, where MIN_LEN <= n <= max_len
    :return:
    """
    if not (len(T) == TWEAK_LEN):
        raise ValueError(f"Tweak must be {TWEAK_LEN} bits")

    if not (MIN_LEN <= len(plainNumerals) <= max_len(radix)):
        raise ValueError(f"Plaintext must have length between {MIN_LEN} and {max_len(radix)}")

    cdef int n = len(plainNumerals)
    cdef int u = int(ceil(n / 2.0))
    cdef int v = n - u
    cdef int t = len(T)
    cdef int i
    cdef int m
    cdef int l

    cdef int * numerals = <int *> malloc(n*sizeof(int))
    cdef int *A = <int *> malloc(u*sizeof(int))
    cdef int *B = <int *> malloc(v*sizeof(int))
    cdef int *C = <int *> malloc(u*sizeof(int))
    cdef unsigned char* tweak = <unsigned char *> malloc(t*sizeof(char))
    cdef unsigned char* tweak_left = <unsigned char *> malloc(4*sizeof(char))
    cdef unsigned char* tweak_right = <unsigned char *> malloc(4*sizeof(char))
    cdef unsigned char* round_array = <unsigned char *> malloc(4*sizeof(char))

    for i in range(t):
        tweak[i] = T[i]

    i = 0

    for i in range(n):
        numerals[i] = plainNumerals[i]

    i = 0

    for i in range(4):
        round_array[i] = 0x00

    i = 0

    memcpy(A, numerals, u*sizeof(int))
    memcpy(B, numerals+u, v*sizeof(int))
    
    memcpy(tweak_left, tweak, 4*sizeof(char))
    memcpy(tweak_right, tweak+4, 3*sizeof(char))

    tweak_right[3] = tweak_left[3] << 4
    tweak_left[3] = tweak_left[3] & 240

    for i in range(8):
        if (i % 2) == 0:
            m = u
            l = v
            W = tweak_right
        else:
            m = v
            l = u
            W = tweak_left

        round_array[3] = i

        P = xorByteArray(W, round_array, 4) + num_radix(radix, reverseArray(B, l), l).to_bytes(12, 'big')
        S = reverse(cipher.encrypt(reverse(P)))
        y = int.from_bytes(S, 'big')
        c = (num_radix(radix, reverseArray(A, m), m) + y) % (radix ** m)
        C = reverseArray(str_radix(radix, m, c), m)
        memcpy(A, B, l*sizeof(int))
        memcpy(B, C, m*sizeof(int))

    cdef int *SUM = <int *> malloc(n*sizeof(int))

    if not SUM:
        raise MemoryError()

    memcpy(SUM, A, u*sizeof(int))
    memcpy(SUM+u, B, v*sizeof(int))

    cipherNumerals = [value for value in SUM[:n]]
    return cipherNumerals


cdef list decrypt_numeral_string(cipherNumerals, T, radix, cipher):
#    """
#    Decrypt ciphertext encrypted with FF3-1 cipher
#    :param tweak: 56 bit
#    :param numeral_string:
#    :return
#    """
    if not (len(T) == TWEAK_LEN):
        raise ValueError(f"Tweak must be {TWEAK_LEN} bits")

    if not (MIN_LEN <= len(cipherNumerals) <= max_len(radix)):
        raise ValueError(f"Plaintext must have length between {MIN_LEN} and {max_len(radix)}")

    cdef int n = len(cipherNumerals)
    cdef int u = int(ceil(n / 2.0))
    cdef int v = n - u
    cdef int t = len(T)
    cdef int l
    cdef int m
    cdef int i

    cdef int * numerals = <int *> malloc(n*sizeof(int))
    cdef int *A = <int *> malloc(u*sizeof(int))
    cdef int *B = <int *> malloc(v*sizeof(int))
    cdef int *C = <int *> malloc(u*sizeof(int))
    cdef unsigned char* tweak = <unsigned char *> malloc(t*sizeof(char))
    cdef unsigned char* tweak_left = <unsigned char *> malloc(4*sizeof(char))
    cdef unsigned char* tweak_right = <unsigned char *> malloc(4*sizeof(char))
    cdef unsigned char* round_array = <unsigned char *> malloc(4*sizeof(char))

    for i in range(t):
        tweak[i] = T[i]

    i = 0

    for i in range(n):
        numerals[i] = cipherNumerals[i]

    i = 0

    for i in range(4):
        round_array[i] = 0x00

    i = 0

    memcpy(A, numerals, u*sizeof(int))
    memcpy(B, numerals+u, v*sizeof(int))

    memcpy(tweak_left, tweak, 4*sizeof(char))
    memcpy(tweak_right, tweak+4, 3*sizeof(char))

    tweak_right[3] = tweak_left[3] << 4
    tweak_left[3] = tweak_left[3] & 240

    for i in range(7, -1, -1):
        if (i % 2) == 0:
            m = u
            l = v
            W = tweak_right
        else:
            m = v
            l = u
            W = tweak_left

        round_array[3] = i

        P = xorByteArray(W, round_array, 4) + num_radix(radix, reverseArray(A, l), l).to_bytes(12, 'big')
        S = reverse(cipher.encrypt(reverse(P)))
        y = int.from_bytes(S, 'big')
        c = (num_radix(radix, reverseArray(B, m), m) - y) % (radix ** m)
        C = reverseArray(str_radix(radix, m, c), m)
        memcpy(B, A, l*sizeof(int))
        memcpy(A, C, m*sizeof(int))

    cdef int *SUM = <int *> malloc(n*sizeof(int))

    if not SUM:
        raise MemoryError()

    memcpy(SUM, A, u*sizeof(int))
    memcpy(SUM+u, B, v*sizeof(int))

    plainNumerals = [value for value in SUM[:n]]
    return plainNumerals

cpdef list encrypt(list numerals,bytes key,bytes T, radix):
    cipher = AES.new(key, AES.MODE_ECB)
    return encrypt_numeral_string(numerals, T, radix, cipher)

cpdef list decrypt(list numerals,bytes key,bytes T, radix):
    cipher = AES.new(key, AES.MODE_ECB)
    return decrypt_numeral_string(numerals, T, radix, cipher)