# need real radix
# need real Tweak and t
# need own ceil func
import math
from utils import num_radix, str_radix,map_from_numeral_string
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from enum import Enum, auto
import time
import binascii

start_time = time.time()

class Format(Enum):
    INT_10DIGIT = auto()
    CREDITCARD = auto()
    STRING = auto()
    EMAIL = auto()
    DATE = auto()
    NAME = auto()

letters = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']
numbers = ['0','1','2','3','4','5','6','7','8','9','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25']

letters2 = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']
numbers2 = ['0','1','2','3','4','5','6','7','8','9','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28','29','30','31','32','33','34','35']

nameDictE = dict(zip(letters,numbers))
nameDictD = dict(zip(numbers,letters))

stringDictE = dict(zip(letters2,numbers2))
stringDictD = dict(zip(numbers2,letters2))

T = bytes.fromhex('3737373770717273373737')
key = bytes.fromhex('2B7E151628AED2A6ABF7158809CF4F3C')
cipher = AES.new(key, AES.MODE_ECB)

def bitstring_to_bytes(s):
    v = int(s, 2)
    b = bytearray()
    while v:
        b.append(v & 0xff)
        v >>= 8
    return bytes(b[::-1])

def PRF(X):
    m = int((len(X)*8)/128)
    Y0 =  b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    for j in range(m):
        if (j==0) : 
            Yj = Y0
        Xj =  X[j*16:(j*16)+16]
        Yj = cipher.encrypt(bytes(A^B for A,B in zip(Yj,Xj)))
    return Yj

def encrypt_main(msg,T,key,radix):

    t = len(T)
    n = len(msg)

    u = n//2
    v = n-u
    A = msg[:u]
    B = msg[u:]
    b = math.ceil(math.ceil(v*math.log2(radix))/8)
    d = 4*math.ceil(b/4)+4
    P = b'\x01'+ b'\x02'+b'\x01' + \
        radix.to_bytes(3,'big') + b'\n' + \
        (u % 256).to_bytes(1,'big') + \
        n.to_bytes(4,'big') + t.to_bytes(4,'big')

    for i in range(10):
        Q = T + (0).to_bytes((-t-b-1) % 16,'big') + (i).to_bytes(1,'big') + num_radix(radix,B).to_bytes(b,'big')
        R = PRF(P+Q)
        S = R
        for j in range(1, int(math.ceil(d/16))):
            S = S + cipher.encrypt(bytes(A^B for A,B in zip(R,(j).to_bytes(16,'big'))))
        S = S[:d]
        y = int.from_bytes(S,'big')
        if (i%2 == 0): 
            m=u
        else:
            m=v
        c = (num_radix(radix,A)+y)%radix**m
        C = str_radix(radix,m,c)
        A = B
        B = C
    return(A+B)

def decrypt_main (cphTxt, T, key, radix):
    t = len(T)
    n = len(cphTxt)

    u = n//2
    v = n-u
    A = cphTxt[:u]
    B = cphTxt[u:]
    b = math.ceil(math.ceil(v*math.log2(radix))/8)
    d = 4*math.ceil(b/4)+4
    P = b'\x01'+ b'\x02'+b'\x01' + \
        radix.to_bytes(3,'big') + b'\n' + \
        (u % 256).to_bytes(1,'big') + \
        n.to_bytes(4,'big') + t.to_bytes(4,'big')

    for i in range(9,-1,-1):
        Q = T + (0).to_bytes((-t-b-1) % 16,'big') + (i).to_bytes(1,'big') + num_radix(radix, A).to_bytes(b,'big')
        #print(P)
        R = PRF(P+Q)
        S = R
        for j in range(1, int(math.ceil(d/16))):
            S = S + cipher.encrypt(bytes(A^B for A,B in zip(R,(j).to_bytes(16,'big'))))
        S = S[:d]
        y = int.from_bytes(S,'big')
        if (i%2 == 0): 
            m=u
        else:
            m=v
        c = (num_radix(radix,B)-y)%radix**m
        C = str_radix(radix,m,c)
        B = A
        A = C
    return(A+B)




def encrypt(msg,T,key,format):
    if format == Format.NAME:
        radix = 26
        mapping = nameDictE
        plainNumerals = map_from_numeral_string(msg,mapping)
        cipherNumerals = encrypt_main(plainNumerals,T,key,radix)
        ciphertext = ''.join(map_from_numeral_string(cipherNumerals,nameDictD))
        print(ciphertext)
    if format == Format.STRING:
        radix = 36
        mapping = stringDictE
        plainNumerals = map_from_numeral_string(msg,mapping)
        cipherNumerals = encrypt_main(plainNumerals,T,key,radix)
        ciphertext = ''.join(map_from_numeral_string(cipherNumerals,stringDictD))
        print(ciphertext)
    return ciphertext

def decrypt(msg,T,key,format):
    if format == Format.NAME:
        radix = 26
        mapping = nameDictE
        cipherNumerals = map_from_numeral_string(msg,mapping)
        plainNumerals = decrypt_main(cipherNumerals,T,key,radix)
        plaintext = ''.join(map_from_numeral_string(plainNumerals,nameDictD))
        print(plaintext)
    if format == Format.STRING:
        radix = 36
        mapping = stringDictE
        cipherNumerals = map_from_numeral_string(msg,mapping)
        plainNumerals = decrypt_main(cipherNumerals,T,key,radix)
        plaintext = ''.join(map_from_numeral_string(plainNumerals,stringDictD))
        print(plaintext)
    return plaintext


ciphertext = encrypt('0123456789abcdefghi',T,key,Format.STRING)
decrypt(ciphertext,T,key,Format.STRING)
#print("--- %s seconds ---" % (time.time() - start_time))