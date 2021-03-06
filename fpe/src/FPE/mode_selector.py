import ff1
import ff3
import Mode

def encrypt(plainNumerals,key,tweak,radix,mode):
	if mode == Mode.FF1:
		return ff1.encrypt(plainNumerals,key,tweak,radix)
	elif mode == Mode.FF3:
		return ff3.encrypt(plainNumerals,key,tweak,radix)

def decrypt(cipherNumerals,key,tweak,radix,mode):
	if mode == Mode.FF1:
		return ff1.decrypt(cipherNumerals,key,tweak,radix)
	if mode == Mode.FF3:
		return ff3.decrypt(cipherNumerals,key,tweak,radix)