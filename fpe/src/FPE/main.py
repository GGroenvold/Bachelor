import FPE
import timeit
import random

names = ['Username','Password','Email','PhoneNumber','Cpr-number','Creditcard','adress','city','zip','country']
formats = [FPE.Format.LETTERS, FPE.Format.STRING, FPE.Format.EMAIL, FPE.Format.DIGITS,
		   FPE.Format.CPR, FPE.Format.CREDITCARD,FPE.Format.STRING,FPE.Format.LETTERS,
		   FPE.Format.DIGITS,FPE.Format.LETTERS]

if __name__ == '__main__':
	T = FPE.generate_tweak(7)

	key = FPE.generate_key()

	cipher = FPE.New(key,T,FPE.Mode.FF1)

	ciphertext = cipher.encrypt('12345',"hello")
	plaintext = cipher.decrypt(ciphertext,FPE.Format.DIGITS)

	print(ciphertext)
	print(plaintext)