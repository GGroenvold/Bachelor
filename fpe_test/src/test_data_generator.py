import csv
import testing
import concurrent.futures
import time
from Crypto.Random import get_random_bytes
from format_translator import *

T = bytes.fromhex('3737373770717273373737')

csvFilePath = 'testDataTable.csv'
columnNames = ['Username','Password','Email','PhoneNumber','Cpr-number','Creditcard','Creditcard','Creditcard','Creditcard','Creditcard']
dataExample = ['CoolUsername', 'SecurePassword123', 'Cool@Email.com', '12345678', '1212121211', '1112223334445559','1112223334445559','1112223334445559','1112223334445559','1112223334445559']
dataFormats = [Format.LETTERS, Format.STRING, Format.EMAIL, Format.DIGITS, Format.CPR, Format.CREDITCARD,Format.CREDITCARD,Format.CREDITCARD,Format.CREDITCARD,Format.CREDITCARD    ]

rows = 200000

def encrypt():

    key = get_random_bytes(16)
    ciphertext= []
    for i in range(len(columnNames)):
        ciphertext.append(testing.encrypt(dataExample[i], T, key, dataFormats[i]))

    return ciphertext

if __name__ == '__main__':

    start_time = time.time()

    data = []

    with concurrent.futures.ProcessPoolExecutor() as executor:
        results = [executor.submit(encrypt) for _ in range(rows-1)]
        for f in concurrent.futures.as_completed(results):
            data.append(f.result())

    with open(csvFilePath, 'w',  newline='') as csvFile:
            csvWriter = csv.writer(csvFile, delimiter = ';')
            csvWriter.writerow(columnNames)
            for row in data:
                csvWriter.writerow(row)       
    print("--- %s seconds ---" % (time.time() - start_time))