# Installation

This library uses PyCryptodome which means a C compiler is required.
For Mac and Linux users this is already installed. For Windows users please
follow this guide from PyCryptoDome.

https://pycryptodome.readthedocs.io/en/latest/src/installation.html#windows-from-sources

# Usage

The libray is imported as `from FPE import FPE`.

To generate a tweak use `FPE.generate_tweak(tweak_length)` where tweak_len is the
length of the tweak in bytes. Note that for FF3-1 the tweak_length must be 7 bytes.

To generate a key use `FPE.generate_key()`, this will generate a 16 byte key.

To make a cipher object use `cipher = FPE.New(key,tweak,mode)`

Currently supported modes are `Mode.FF1` and `Mode.FF3-1`

To encrypt use `cipher.encrypt(plaintext,format)`

Currently supported formats are:

`Format.DIGITS`\
`Format.CREDITCARD`\
`Format.LETTERS`\
`Format.STRING`\
`Format.EMAIL`\
`Format.CPR`

to decrypt use `cipher.decrypt(ciphertext,format)`

The library also supports CSV files

To encrypt a csv file use `cipher.encryptCSV(InputFilePath,OutputFilePath,formats)`
where formats is a list of formats sorted by the columns

To decrypt a csv file use `cipher.decryptCSV(InputFilePath,OutputFilePath,formats)`

to generate a random CSV file with certain formats use 
`cipher.generateData(OutputFilePath,rows,formats,variables)` where rows
define the number of rows in the CSV file. Formats is the lists of formats
to use. Variables is the list of variable names used for the first row.

# Examples

Example of encrypting and decrypting "12345" as `DIGITS` and printing the output

```Python
from FPE import FPE

if __name__ == '__main__':

	T = FPE.generate_tweak(8)
	
	key = FPE.generate_key()
	
	cipher = FPE.New(key,T,FPE.Mode.FF1)
	
	ciphertext = cipher.encrypt('12345',FPE.Format.DIGITS)
	
	print(ciphertext)
	
	plaintext = cipher.decrypt(ciphertext,FPE.Format.DIGITS)
	
	print(plaintext)
```

Example of generating, encrypting and decrypting a 1000 row CSV file

```Python
from FPE import FPE, Format

variables = [
	'Username','Password','Email','PhoneNumber','Cpr-number',
	'Creditcard','adress','city','zip','country'
]


formats = [
	Format.LETTERS, Format.STRING, Format.EMAIL, Format.DIGITS,
	Format.CPR, Format.CREDITCARD,Format.STRING,Format.LETTERS,
	Format.DIGITS,Format.LETTERS
]

if __name__ == '__main__':
	
	T = FPE.generate_tweak(7)
	key = FPE.generate_key()
	cipher = FPE.New(key,T,FPE.Mode.FF3)
	cipher.generateData('testData.csv',1000,formats,variables)
	cipher.encryptCSV('testData.csv','encryptedData.csv',formats)
	cipher.decryptCSV('encryptedData.csv','decryptedData.csv',formats)

```