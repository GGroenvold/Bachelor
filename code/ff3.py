import math
from bitstring import BitArray
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

RADIX = 10
MIN_LEN, MAX_LEN = 6, 10
TWEAK_LEN = 56


class FF3:
    def __init__(self, K, radix=RADIX):
        self.K = K
        self.radix = radix
        self.cipher = AES.new(K, AES.MODE_ECB)

    def encrypt(self, T, X):
        n = len(X)
        u = int(math.ceil(n / 2))
        v = n - u

        A, B = X[:u], X[u:]

        Tl = BitArray(T[:28]) + BitArray('0b0000')
        Tr = BitArray(T[32:56]) + BitArray(T[28:32]) + BitArray('0b0000')

        for i in range(8):
            if (i % 2) == 0:
                m = u
                W = Tr
            else:
                m = v
                W = Tl

            # TODO: Use correct order of significance
            P = (W ^ BitArray(i.to_bytes(4, 'big'))) + int(B).to_bytes(12, 'big')
            S = self.cipher.encrypt(P.bytes)
            y = int.from_bytes(S, 'big')
            c = (int(A) + y) % (self.radix ** m)

            C = str(int(c))
            A = B
            B = C

        return A + B

    def decrypt(self, T, X):
        n = len(X)
        u = int(math.ceil(n / 2))
        v = n - u
        A, B = X[:u], X[u:]

        Tl = BitArray(T[:28]) + BitArray('0b0000')
        Tr = BitArray(T[32:56]) + BitArray(T[28:32]) + BitArray('0b0000')

        for i in reversed(range(8)):
            if (i % 2) == 0:
                m = u
                W = Tr
            else:
                m = v
                W = Tl

            P = (W ^ BitArray(i.to_bytes(4, 'big'))) + int(A).to_bytes(12, 'big')
            S = self.cipher.encrypt(P.bytes)
            y = int.from_bytes(S, 'big')
            c = (int(B) - y) % (self.radix ** m)

            C = str(int(c))
            B = A
            A = C

        return A + B


if __name__ == '__main__':
    T = BitArray(get_random_bytes(TWEAK_LEN // 8))
    K = get_random_bytes(16)

    ff3_cypher = FF3(K)

    X = '1234567'

    ciphertext = ff3_cypher.encrypt(T, X)
    plaintext = ff3_cypher.decrypt(T, ciphertext)

    print(ciphertext)
    print(plaintext)
