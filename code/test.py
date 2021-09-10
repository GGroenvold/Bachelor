from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


key = get_random_bytes(16)
plaintext = b'This is a test'

f = open("data.txt", "rb")
data = f.read()

encrypt_cipher = AES.new(key, AES.MODE_CBC)
ciphertext = encrypt_cipher.encrypt(pad(data, AES.block_size))

decrypt_cipher = AES.new(key, AES.MODE_CBC, encrypt_cipher.iv)

print(ciphertext)
print(unpad(decrypt_cipher.decrypt(ciphertext), AES.block_size))
