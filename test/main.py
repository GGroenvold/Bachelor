from FPE import FPE, Format

if __name__ == '__main__':
	tweak = FPE.generate_tweak(0)

#	key = FPE.generate_key()

	key = b"\xdb\xcb\xb3/\x8c\x00\x93|\x8b1\x91<\x8f\x7f\xeb'"

	cipher = FPE.New(key,tweak,FPE.Mode.FF1)

	ciphertext = cipher.encrypt('example@email.com',Format.EMAIL)
	plaintext = cipher.decrypt(ciphertext,Format.EMAIL)

	print('ciphertext: ' + ciphertext)
	print('plaintext: ' + plaintext)