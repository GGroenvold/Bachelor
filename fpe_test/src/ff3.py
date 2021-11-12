from math import ceil
from bitstring import BitArray
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from utils import num_radix, str_radix, reverse
from format_translator import *

# Constants
MIN_LEN, MAX_LEN = 2, 100
TWEAK_LEN = 56
MAPPING = Format.DIGITS
FORMAT = Format.DEFAULT


class FF3:

    def __init__(self, key):
        self.key = reverse(key)
        self.cipher = AES.new(key, AES.MODE_ECB)

    def encrypt_numeral_string(self, tweak, radix, numeral_string):
        """
        Encrypt plaintext with FF3-1 cipher
        :param tweak: 56 bit
        :param numeral_string: numeral string with length n, where 6 <= n <= 10
        :return:
        """
        if not (len(tweak) == TWEAK_LEN):
            raise ValueError(f"Tweak must be {TWEAK_LEN} bits")

        if not (MIN_LEN <= len(numeral_string) <= MAX_LEN):
            raise ValueError(f"Plaintext must have length between {MIN_LEN} and {MAX_LEN}")

        n = len(numeral_string)
        u = int(ceil(n / 2))
        v = n - u

        # Split numeral string into two parts
        A, B = numeral_string[:u], numeral_string[u:]

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

            # TODO: Refactor P
            P = (W ^ BitArray(i.to_bytes(4, 'big'))) + BitArray(num_radix(radix, reverse(B)).to_bytes(12, 'big'))
            S = reverse(self.cipher.encrypt(bytes(reverse(P))))
            y = int.from_bytes(S, 'big')
            c = (num_radix(radix, reverse(A)) + y) % (radix ** m)

            C = reverse(str_radix(radix, m, c))
            A = B
            B = C

        return A + B

    def encrypt(self, tweak, plaintext, format=FORMAT):
        numeral_string = plaintext_to_numeral_string(plaintext, format)
        radix = get_radix_by_format(format)

        ciphertext = self.encrypt_numeral_string(tweak, radix, numeral_string)

        return ''.join(numeral_string_to_plaintext(ciphertext, format))

    def decrypt_numeral_string(self, tweak, radix, numeral_string):
        """
        Decrypt ciphertext encrypted with FF3-1 cipher
        :param tweak: 56 bit
        :param numeral_string:
        :return
        """
        if not (len(tweak) == TWEAK_LEN):
            raise ValueError(f"Tweak must be {TWEAK_LEN} bits")

        if not (MIN_LEN <= len(numeral_string) <= MAX_LEN):
            raise ValueError(f"Ciphertext must have length between {MIN_LEN} and {MAX_LEN}")

        n = len(numeral_string)
        u = int(ceil(n / 2))
        v = n - u
        A, B = numeral_string[:u], numeral_string[u:]

        tweak_left = BitArray(tweak[:28]) + BitArray('0b0000')
        tweak_right = BitArray(tweak[32:56]) + BitArray(tweak[28:32]) + BitArray('0b0000')

        for i in reversed(range(8)):
            if (i % 2) == 0:
                m = u
                W = tweak_right
            else:
                m = v
                W = tweak_left

            P = (W ^ BitArray(i.to_bytes(4, 'big'))) + BitArray(num_radix(radix, reverse(A)).to_bytes(12, 'big'))
            S = reverse(self.cipher.encrypt(bytes(reverse(P))))
            y = int.from_bytes(S, 'big')
            c = (num_radix(radix, reverse(B)) - y) % (radix ** m)

            C = reverse(str_radix(radix, m, c))
            B = A
            A = C

        return A + B

    def decrypt(self, tweak, ciphertext, format=FORMAT):
        cipher_numeral_string = plaintext_to_numeral_string(ciphertext, format)
        radix = get_radix_by_format(format)
        ciphertext = self.decrypt_numeral_string(tweak, radix, cipher_numeral_string)

        return ''.join(numeral_string_to_plaintext(ciphertext, format))


if __name__ == '__main__':
    tweak = BitArray(get_random_bytes(TWEAK_LEN // 8))
    key = get_random_bytes(16)

    ff3_cipher = FF3(key)

    X = "abababababababababababababab"

    print(X)

    ciphertext = ff3_cipher.encrypt(tweak, X, Format.STRING)
    plaintext = ff3_cipher.decrypt(tweak, ciphertext, Format.STRING)

    print(ciphertext)
    print(plaintext)
