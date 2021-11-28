import FPE
import timeit
import random
from format_translator import validateCPR, validateCard

names = ['Username','Password','Email','PhoneNumber','Cpr-number','Creditcard','adress','city','zip','country']
formats = [FPE.Format.LETTERS, FPE.Format.STRING, FPE.Format.EMAIL, FPE.Format.DIGITS,
		   FPE.Format.CPR, FPE.Format.CREDITCARD,FPE.Format.STRING,FPE.Format.LETTERS,
		   FPE.Format.DIGITS,FPE.Format.LETTERS]

if __name__ == '__main__':
	T = FPE.generate_tweak(7)

	key = b'O\xa8\x8c\x9d\xbd\xbe\xa5\xbe3WL\xb2\xf6\x88~\xe3'
	ff1 = FPE.New(key,T,FPE.Mode.FF3)
	print(1)
	ciphertext = ff1.encrypt('a33*', FPE.Format.STRING)
	plaintext = ff1.decrypt(ciphertext,FPE.Format.STRING)
	print(2)
	ciphertext = ff1.encrypt('1234 1234 1234 123'+validateCard('123412341234123'), FPE.Format.CREDITCARD)
	plaintext = ff1.decrypt(ciphertext,FPE.Format.CREDITCARD)
	print(3)
	ciphertext = ff1.encrypt('123456', FPE.Format.DIGITS)
	plaintext = ff1.decrypt(ciphertext,FPE.Format.DIGITS)
	print(4)
	ciphertext = ff1.encrypt('1234@aaaa.com', FPE.Format.EMAIL)
	plaintext = ff1.decrypt(ciphertext,FPE.Format.EMAIL)
	print(5)
	ciphertext = ff1.encrypt('abcf', FPE.Format.LETTERS)
	plaintext = ff1.decrypt(ciphertext,FPE.Format.LETTERS)
	print(6)
	ciphertext = ff1.encrypt('3012567897', FPE.Format.CPR)
	plaintext = ff1.decrypt(ciphertext,FPE.Format.CPR)
	print(7)

	print(ciphertext)
	print(plaintext)