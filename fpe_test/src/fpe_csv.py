import csv
import concurrent.futures
import json
import FPE
import time
from Crypto.Random import get_random_bytes
from format_translator import *
from timeit import default_timer as timer

dataExample = ['12345678','1112223334445559','CoolUsername','SecurePassword123','Cool@Email.com','1212121211']
dataFormats = [Format.DIGITS,Format.CREDITCARD,Format.LETTERS,Format.STRING,Format.EMAIL,Format.CPR]

mapping_formats = dict(zip(dataFormats, dataExample))

def generate_data(columns,dataFormat,mode):
    T = FPE.generate_tweak(7)
    key = FPE.generate_key()
    fpe = FPE.New(key,T,mode)


    ciphertexts = [columns[0]]

    for msg in columns[1:]:
        fpe.set_key(FPE.generate_key())
        ciphertexts.append(fpe.encrypt(msg,dataFormat))
    return ciphertexts

def encrypt(columns,dataFormat,key,tweak,mode):

    fpe = FPE.New(key,tweak,mode)

    ciphertexts = [columns[0]]

    for msg in columns[1:]:
        ciphertexts.append(fpe.encrypt(msg,dataFormat))


    return ciphertexts

def decrypt(columns,dataFormat,key,tweak,mode):

    fpe = FPE.New(key,tweak,mode)

    ciphertexts = [columns[0]]

    for msg in columns[1:]:
        ciphertexts.append(fpe.decrypt(msg,dataFormat))

    return ciphertexts

def encrypt_csv(csvFilePath,encryptedFilePath,formats,fpe):
    start = timer()
    print('Encrypting...')
    n = len(formats)

    data=[]

    keys = [fpe.key]*n
    tweaks = [fpe.tweak]*n
    modes = [fpe.mode]*n

    with open(csvFilePath) as csvFile:
        csvReader = csv.reader(csvFile, delimiter = ';')
        rowCount = 0
        for row in csvReader:
            if (rowCount != 0):
                columnCount = 0
                for column in row:
                    data[columnCount].append(column)
                    columnCount += 1

                #print("%d %d" %(rowCount, columnCount))
            else:
                for column in row:
                    data.append([column])
            
                rowCount += 1

    with concurrent.futures.ProcessPoolExecutor() as executor:
        results = list(executor.map(encrypt,data,formats,keys,tweaks,modes))

        data = results


    with open(encryptedFilePath, 'w',  newline='') as encryptedCSVFile:
        csvWriter = csv.writer(encryptedCSVFile, delimiter = ';')
        for i in range(len(data[0])):
            data2 = []
            for j in range(len(data)):
                #print(i)
                #print(data[j][i])
                data2.append(data[j][i])
            csvWriter.writerow(data2)

    end = timer()
    print('Done in %5.2f seconds' % (end-start))

def decrypt_csv(csvFilePath,decryptedFilePath,formats,fpe):
    start = timer()
    print('Decrypting...')
    n = len(formats)

    data=[]

    keys = [fpe.key]*n
    tweaks = [fpe.tweak]*n
    modes = [fpe.mode]*n

    with open(csvFilePath) as csvFile:
        csvReader = csv.reader(csvFile, delimiter = ';')
        rowCount = 0
        for row in csvReader:
            if (rowCount != 0):
                columnCount = 0
                for column in row:
                    data[columnCount].append(column)
                    columnCount += 1

                #print("%d %d" %(rowCount, columnCount))
            else:
                for column in row:
                    data.append([column])
            
                rowCount += 1

    with concurrent.futures.ProcessPoolExecutor() as executor:
        results = list(executor.map(decrypt,data,formats,keys,tweaks,modes))

        data = results


    with open(decryptedFilePath, 'w',  newline='') as decryptedCSVFile:
        csvWriter = csv.writer(decryptedCSVFile, delimiter = ';')
        for i in range(len(data[0])):
            data2 = []
            for j in range(len(data)):
                #print(i)
                #print(data[j][i])
                data2.append(data[j][i])
            csvWriter.writerow(data2)

    end = timer()
    print('Done in %5.2f seconds' % (end-start))

def generate_test_data(csvFilePath,rows,formats,names, mode):
    start = timer()
    print('Generating...')
    data = [[x] for x in names]

    modes = [mode]*len(formats)

    for i in range(len(names)):
        for _ in range(rows):
            data[i].append(mapping_formats[formats[i]])

    with concurrent.futures.ProcessPoolExecutor() as executor:
        results = list(executor.map(generate_data,data,formats,modes))

        data = results



    with open(csvFilePath, 'w',  newline='') as csvFile:
            csvWriter = csv.writer(csvFile, delimiter = ';')
            for i in range(len(data[0])):
                data2 = []
                for j in range(len(data)):
                    #print(i)
                    #print(data[j][i])
                    data2.append(data[j][i])
                csvWriter.writerow(data2)
    
    end = timer()
    print('Done in %5.2f seconds' % (end-start))