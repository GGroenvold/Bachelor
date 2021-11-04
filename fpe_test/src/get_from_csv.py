import csv
import json
import ff1
import time
from Crypto.Random import get_random_bytes
from format_translator import *
if __name__ == '__main__':


    start_time = time.time()
    
    T = bytes.fromhex('3737373770717273373737')
    key = bytes.fromhex('2B7E151628AED2A6ABF7158809CF4F3C')
    csvFilePath = 'testDataTable.csv'
    encryptedDataPath = 'encryptedData.csv'
    dataFormats = [Format.LETTERS, Format.STRING, Format.EMAIL, Format.DIGITS, Format.CPR, Format.CREDITCARD]    
 
    data=[]
    with open(csvFilePath) as csvFile:
        csvReader = csv.reader(csvFile, delimiter = ';')
        rowCount = 0
        for row in csvReader:
            if (rowCount != 0):
                columnCount = 0
                for column in row:
                    print("%d %d" %(rowCount, columnCount))
                    data[columnCount].append(ff1.encrypt(column, T, key, dataFormats[columnCount]))
                    columnCount += 1
            else:
                for column in row:
                    data.append([column])
            
            rowCount += 1

    with open(encryptedDataPath, 'w',  newline='') as encryptedCSVFile:
        csvWriter = csv.writer(encryptedCSVFile, delimiter = ';')
        for i in range(len(data[0])):
            data2 = []
            for j in range(len(data)):
                print(i)
                print(data[j][i])
                data2.append(data[j][i])
            csvWriter.writerow(data2)

    print("--- %s seconds ---" % (time.time() - start_time))

#    data = json.loads(open("names.json", "r").read())
#    names = []
#    numbers = []
#    for name in data['names']:
#        names.append(name['name'].lower())
#        numbers.append(name['number'])


    # read synthetic lookup table
    #csvFilePath = 'SyntheticTable.csv'
    #data = []
    #columnNames = []
    #i=0
    #with open(csvFilePath) as csvFile:
    #    csvReader = csv.reader(csvFile,delimiter = ';')
    #    for rows in csvReader:
    #        if (i != 0):
    #            for column in range(len(rows)):
    #                print(rows[column])
    #                data[column].append(ff1.encrypt(rows[column], T, key, Format.STRING))
    #            i=i+1
    #        else:
    #            for index in range(len(rows)):
    #                columnNames.append(rows[index])
    #                data.append([])
    #            i=i+1