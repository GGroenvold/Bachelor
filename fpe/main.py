from FPE import FPE
import timeit
import random

names = ['Username','Password','Email','PhoneNumber','Cpr-number','Creditcard','adress','city','zip','country']
formats = [FPE.Format.LETTERS, FPE.Format.STRING, FPE.Format.EMAIL, FPE.Format.DIGITS,
		   FPE.Format.CPR, FPE.Format.CREDITCARD,FPE.Format.STRING,FPE.Format.LETTERS,
		   FPE.Format.DIGITS,FPE.Format.LETTERS]

def encrypt_something():
	start = timeit.default_timer()

	T = FPE.generate_tweak(7)

	key = FPE.generate_key()

	ff1 = FPE.New(key,T,FPE.Mode.FF1)

#	randomlist = []

#	for _ in range(1000):
#		n = random.randint(0,9)
#		randomlist.append(n)
#
#	input = ''.join([str(x) for x in randomlist])

	for _ in range(1):
		ciphertext = ff1.encrypt('12345',FPE.Format.DIGITS)
		plaintext = ff1.decrypt(ciphertext,FPE.Format.DIGITS)

	print(ciphertext)
	print(plaintext)

	stop = timeit.default_timer()

	print('Time: ', stop - start)

if __name__ == '__main__':
	T = FPE.generate_tweak(7)

	key = FPE.generate_key()

	ff1 = FPE.New(key,T,FPE.Mode.FF1)

	ciphertext = ff1.encrypt('12345',FPE.Format.DIGITS)
	plaintext = ff1.decrypt(ciphertext,FPE.Format.DIGITS)

	print(ciphertext)
	print(plaintext)