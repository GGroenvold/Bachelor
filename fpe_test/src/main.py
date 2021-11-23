import FPE
import timeit
import random

names = ['Username','Password','Email','PhoneNumber','Cpr-number','Creditcard']
formats = [FPE.Format.LETTERS, FPE.Format.STRING, FPE.Format.EMAIL, FPE.Format.DIGITS, FPE.Format.CPR, FPE.Format.CREDITCARD]

def encrypt_something():
	start = timeit.default_timer()

	T = FPE.generate_tweak(7)

	key = FPE.generate_key()

	ff1 = FPE.New(key,T,FPE.Mode.FF3)

	randomlist = []

#	for _ in range(1000):
#		n = random.randint(0,9)
#		randomlist.append(n)
#
#	input = ''.join([str(x) for x in randomlist])

	#for _ in range(100000):
	ciphertext = ff1.encrypt('12345',FPE.Format.DIGITS)
	plaintext = ff1.decrypt(ciphertext,FPE.Format.DIGITS)

	print(ciphertext)
	print(plaintext)

	stop = timeit.default_timer()

	print('Time: ', stop - start)

if __name__ == '__main__':
	#encrypt_something()
	
	T = FPE.generate_tweak(7)
	key = FPE.generate_key()
	ff1 = FPE.New(key,T,FPE.Mode.FF1)
	
	#ff1.generateData('src/testData.csv',100000,formats,names)
	
	ff1.encryptCSV('src/testData.csv','src/encryptedData.csv',formats)
	ff1.decryptCSV('src/encryptedData.csv','src/decryptedData.csv',formats)