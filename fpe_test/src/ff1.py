# need real radix
# need real Tweak and t
# need own ceil func
import math
from utils import num_radix, str_radix
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

msg = '0123456789'
T = b'\x00\x10'
key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_ECB)
def PRF(X):
    m = int((len(X)*8)/128)
    Y0 =  b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    for j in range(m):
        if (j==0) : 
            Yj = Y0
        Xj =  X[j*16:(j*16)+16]
        Yj = cipher.encrypt(bytes(A^B for A,B in zip(Yj,Xj)))
    return Yj

def encrypt(msg,T,key):
    radix = 10
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
        Q = T + (0).to_bytes((-t-b-1) % 16,'big') + (i).to_bytes(1,'big') + num_radix(radix, B).to_bytes(b,'big')
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

def decrypt (cphTxt, T, key):
    radix = 10
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
cphTxt = encrypt(msg,T,key)

print(cphTxt)
print(decrypt(cphTxt,T,key))