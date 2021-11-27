import pytest
from ff3.ff3 import FF3
from bitstring import BitArray

KEY = b'2\\\x9f\xbb\xd9\x91X4[dP\xc90\x14\xa5\xd8'
TWEAK = BitArray('0xe7e2f5d699b30c')
PLAINTEXTS = {'123456', '1234567'}


@pytest.fixture
def ff3_cipher():
    return FF3(KEY)


def test_encrypt_plaintext_format(ff3_cipher):
    with pytest.raises(ValueError):
        assert ff3_cipher.encrypt_numeral_string(TWEAK, '123')
        assert ff3_cipher.encrypt_numeral_string(TWEAK, '12345678910')


def test_encrypt_tweak_format(ff3_cipher):
    with pytest.raises(ValueError):
        assert ff3_cipher.encrypt_numeral_string(BitArray('0b0000'), '123456')
        assert ff3_cipher.encrypt_numeral_string(BitArray('0xe7e2f5d699b30c10'), '123456')


@pytest.mark.parametrize("plaintext", PLAINTEXTS)
def test_decrypt(ff3_cipher, plaintext):
    ciphertext = ff3_cipher.encrypt_numeral_string(TWEAK, plaintext)
    assert ff3_cipher.decrypt_numeral_string(TWEAK, ciphertext) == plaintext
