from math import ceil
import logging
from bitstring import BitArray
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Constants
RADIX = 10
MIN_LEN, MAX_LEN = 6, 10
TWEAK_LEN = 56


class FF3:

    def __init__(self, key, radix=RADIX):
        self.K = key
        self.radix = radix
        self.cipher = AES.new(key, AES.MODE_ECB)

    def encrypt(self, tweak, plaintext):
        """

        :param tweak: 56 bit
        :param plaintext:
        :return:
        """
        if not (len(tweak) == TWEAK_LEN):
            raise ValueError(f"Tweak must be {TWEAK_LEN} bits")

        if not (MIN_LEN <= len(plaintext) <= MAX_LEN):
            raise ValueError(f"Plaintext must have length between {MIN_LEN} and {MAX_LEN}")

        n = len(plaintext)
        u = int(ceil(n / 2))
        v = n - u

        # Split numeral string into two parts
        A, B = plaintext[:u], plaintext[u:]

        # Construct a left and right tweak of 32 bits
        tweak_left = BitArray(tweak[:28]) + BitArray('0b0000')
        tweak_right = BitArray(tweak[32:56]) + BitArray(tweak[28:32]) + BitArray('0b0000')

        for i in range(8):
            if (i % 2) == 0:
                m = u
                W = tweak_right
            else:
                m = v
                W = tweak_left

            # TODO: Use correct order of significance
            P = (W ^ BitArray(i.to_bytes(4, 'big'))) + int(B).to_bytes(12, 'big')
            S = self.cipher.encrypt(P.bytes)
            y = int.from_bytes(S, 'big')
            c = (int(A) + y) % (self.radix ** m)

            C = str(int(c))
            A = B
            B = C

        return A + B

    def decrypt(self, tweak, ciphertext):
        """
        Decrypt ciphertext encrypted with FF3-1 cipher
        :param tweak: 56 bit
        :param ciphertext:
        :return:
        """
        if not (len(tweak) == TWEAK_LEN):
            raise ValueError(f"Tweak must be {TWEAK_LEN} bits")

        if not (MIN_LEN <= len(ciphertext) <= MAX_LEN):
            raise ValueError(f"Plaintext must have length between {MIN_LEN} and {MAX_LEN}")

        n = len(ciphertext)
        u = int(ceil(n / 2))
        v = n - u
        A, B = ciphertext[:u], ciphertext[u:]

        tweak_left = BitArray(tweak[:28]) + BitArray('0b0000')
        tweak_right = BitArray(tweak[32:56]) + BitArray(tweak[28:32]) + BitArray('0b0000')

        for i in reversed(range(8)):
            if (i % 2) == 0:
                m = u
                W = tweak_right
            else:
                m = v
                W = tweak_left

            P = (W ^ BitArray(i.to_bytes(4, 'big'))) + int(A).to_bytes(12, 'big')
            S = self.cipher.encrypt(P.bytes)
            y = int.from_bytes(S, 'big')
            c = (int(B) - y) % (self.radix ** m)

            C = str(int(c))
            B = A
            A = C

        return A + B


if __name__ == '__main__':
    tweak = BitArray(get_random_bytes(TWEAK_LEN // 8))
    key = get_random_bytes(16)

    print(tweak)
    print(key)

    ff3_cipher = FF3(key)

    X = '1234567'

    ciphertext = ff3_cipher.encrypt(tweak, X)
    plaintext = ff3_cipher.decrypt(tweak, ciphertext)

    print(ciphertext)
    print(plaintext)
