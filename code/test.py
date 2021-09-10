from Crypto.Cipher import AES
from Crypto.Util import Padding

key = b'Sixteen byte key'
plaintext = Padding.pad(b'This', 16)

cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(plaintext)

decrypt_cipher = AES.new(key, AES.MODE_ECB)

print(ciphertext)
print(Padding.unpad(decrypt_cipher.decrypt(ciphertext), 16))
