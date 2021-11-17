import FPE
import timeit
from fpe_csv import encrypt_csv,decrypt_csv,generate_test_data

names = ['Username','Password','Email','PhoneNumber','Cpr-number','Creditcard']
formats = [FPE.FORMAT_LETTERS, FPE.FORMAT_STRING, FPE.FORMAT_EMAIL, FPE.FORMAT_DIGITS, FPE.FORMAT_CPR, FPE.FORMAT_CREDITCARD]

def encrypt_something():
	start = timeit.default_timer()

	T = FPE.generate_tweak(8)


	key = FPE.generate_key()

	ff1 = FPE.New(key,T,FPE.MODE_FF1)

	ciphertext = ff1.encrypt('example@email.com',FPE.FORMAT_EMAIL)
	plaintext = ff1.decrypt(ciphertext,FPE.FORMAT_EMAIL)

	print(ciphertext)
	print(plaintext)

	stop = timeit.default_timer()

	print('Time: ', stop - start)

if __name__ == '__main__':
	#encrypt_something()
	#generate_test_data('src/testData.csv',100000,formats,names,FPE.MODE_FF1)
	
	T = FPE.generate_tweak(8)
	key = FPE.generate_key()
	ff1 = FPE.New(key,T,FPE.MODE_FF1)
	
	#encrypt_csv('src/testData.csv','src/encryptedData.csv',formats,ff1)
	decrypt_csv('src/encryptedData.csv','src/decryptedData.csv',formats,ff1)