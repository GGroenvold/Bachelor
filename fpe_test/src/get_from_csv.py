import csv
import json
if __name__ == '__main__':

#    data = json.loads(open("names.json", "r").read())
#    names = []
#    numbers = []
#    for name in data['names']:
#        names.append(name['name'].lower())
#        numbers.append(name['number'])





    csvFilePath = 'top-lvl-domains.csv'
    jsonFilePath = 'top-lvl-domains.json'
    data = {}
    data['top-lvl-domains']=[]
    with open(csvFilePath) as csvFile:
        csvReader = csv.DictReader(csvFile)
        for rows in csvReader:
            data['top-lvl-domains'].append({
                'top-lvl-domain': rows['top-lvl-domains'].lower()})
    with open(jsonFilePath, 'w') as jsonFile:
        jsonFile.write(json.dumps(data, indent = 4))

