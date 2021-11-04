import csv
import ff1
import time
from Crypto.Random import get_random_bytes
from format_translator import *
if __name__ == '__main__':


    start_time = time.time()
    
    T = bytes.fromhex('3737373770717273373737')

    csvFilePath = 'testDataTable.csv'
    columnNames = ['Username','Password','Email','PhoneNumber','Cpr-number','Creditcard']
    dataExample = ['CoolUsername', 'SecurePassword123', 'Cool@Email.com', '12345678', '1212121211', '1112223334445559']
    dataFormats = [Format.LETTERS, Format.STRING, Format.EMAIL, Format.DIGITS, Format.CPR, Format.CREDITCARD]
    
 
    with open(csvFilePath, 'w',  newline='') as csvFile:
        csvWriter = csv.writer(csvFile, delimiter = ';')
        for i in range(1000):
            print(i)
            data=[]
            if (i != 0):
                key = get_random_bytes(16)
                for column in range(len(columnNames)):
                    data.append(ff1.encrypt(dataExample[column], T, key, dataFormats[column]))

            else:
                for index in range(len(columnNames)):
                    data.append(columnNames[index])
            csvWriter.writerow(data)
    
    print("--- %s seconds ---" % (time.time() - start_time))