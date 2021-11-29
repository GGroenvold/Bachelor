import FPE
from timeit import default_timer as timer
import random
from format_translator import validateCPR, validateCard

names = ['Username','Password','Email','PhoneNumber','Cpr-number','Creditcard','adress','city','zip','country']
formats = [FPE.Format.LETTERS, FPE.Format.STRING, FPE.Format.EMAIL, FPE.Format.DIGITS,
		   FPE.Format.CPR, FPE.Format.CREDITCARD,FPE.Format.STRING,FPE.Format.LETTERS,
		   FPE.Format.DIGITS,FPE.Format.LETTERS]

if __name__ == '__main__':
	start = timer()
	T = FPE.generate_tweak(7)
	key = b'O\xa8\x8c\x9d\xbd\xbe\xa5\xbe3WL\xb2\xf6\x88~\xe3'
	ff1 = FPE.New(key,T,FPE.Mode.FF3)
	
	for _ in range(1):	
		ciphertext = ff1.encrypt('123456', FPE.Format.DIGITS)
		plaintext = ff1.decrypt(ciphertext,FPE.Format.DIGITS)

	print(ciphertext)
	print(plaintext)

	end = timer()
	print('Done in %5.2f seconds' % (end-start))