#Ceil function
import math
from utils import num_radix, str_radix,map_from_numeral_string, map_from_name
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from enum import Enum, auto
import time
import binascii
import json
from numpy import arange

start_time = time.time()

class Format(Enum):
    DIGITS = auto()
    CREDITCARD = auto()
    LETTERS = auto()
    STRING = auto()
    EMAIL = auto()
    DATE = auto()
    NAME = auto()

letters = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']
numbers = ['0','1','2','3','4','5','6','7','8','9','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25']

letters2 = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']
numbers2 = ['0','1','2','3','4','5','6','7','8','9','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28','29','30','31','32','33','34','35']

lettersDictE = dict(zip(letters,numbers))
lettersDictD = dict(zip(numbers,letters))

stringDictE = dict(zip(letters2,numbers2))
stringDictD = dict(zip(numbers2,letters2))

T = bytes.fromhex('3737373770717273373737')
key = bytes.fromhex('2B7E151628AED2A6ABF7158809CF4F3C')
cipher = AES.new(key, AES.MODE_ECB)

def PRF(X):
    m = int((len(X)*8)/128)
    Y0 =  b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    for j in range(m):
        if (j==0) : 
            Yj = Y0
        Xj =  X[j*16:(j*16)+16]
        Yj = cipher.encrypt(bytes(A^B for A,B in zip(Yj,Xj)))
    return Yj

def get_mapping_from_domain(domain):
    index = list(map(str, arange(1,len(domain)+1).tolist()))
    return [dict(zip(domain,index)), dict(zip(index,domain))]

def encrypt_main(msg,T,key,radix):

    t = len(T)
    n = len(msg)

    u = n//2
    v = n-u
    A = msg[:u]
    B = msg[u:]
    b = math.ceil(math.ceil(v*math.log2(radix))/8)
    d = 4*math.ceil(b/4)+4
    P = b'\x01'+ b'\x02'+b'\x01' + \
        radix.to_bytes(3,'big') + b'\n' + \
        (u % 256).to_bytes(1,'big') + \
        n.to_bytes(4,'big') + t.to_bytes(4,'big')

    for i in range(10):
        Q = T + (0).to_bytes((-t-b-1) % 16,'big') + (i).to_bytes(1,'big') + num_radix(radix,B).to_bytes(b,'big')
        R = PRF(P+Q)
        S = R
        for j in range(1, int(math.ceil(d/16))):
            S = S + cipher.encrypt(bytes(A^B for A,B in zip(R,(j).to_bytes(16,'big'))))
        S = S[:d]
        y = int.from_bytes(S,'big')
        if (i%2 == 0): 
            m=u
        else:
            m=v
        c = (num_radix(radix,A)+y)%radix**m
        C = str_radix(radix,m,c)
        A = B
        B = C
    return(A+B)

def decrypt_main (cphTxt, T, key, radix):
    t = len(T)
    n = len(cphTxt)

    u = n//2
    v = n-u
    A = cphTxt[:u]
    B = cphTxt[u:]
    b = math.ceil(math.ceil(v*math.log2(radix))/8)
    d = 4*math.ceil(b/4)+4
    P = b'\x01'+ b'\x02'+b'\x01' + \
        radix.to_bytes(3,'big') + b'\n' + \
        (u % 256).to_bytes(1,'big') + \
        n.to_bytes(4,'big') + t.to_bytes(4,'big')

    for i in range(9,-1,-1):
        Q = T + (0).to_bytes((-t-b-1) % 16,'big') + (i).to_bytes(1,'big') + num_radix(radix, A).to_bytes(b,'big')
        #print(P)
        R = PRF(P+Q)
        S = R
        for j in range(1, int(math.ceil(d/16))):
            S = S + cipher.encrypt(bytes(A^B for A,B in zip(R,(j).to_bytes(16,'big'))))
        S = S[:d]
        y = int.from_bytes(S,'big')
        if (i%2 == 0): 
            m=u
        else:
            m=v
        c = (num_radix(radix,B)-y)%radix**m
        C = str_radix(radix,m,c)
        B = A
        A = C
    return(A+B)




def encrypt(msg,T,key,format):
    if format == Format.DIGITS:
        radix = 10
        ciphertext = ''.join(encrypt_main(msg, T, key, radix))
        print(ciphertext)
        return ciphertext

    if format == Format.CREDITCARD:
        #how much in depth do we wanna go?
            #do we wanna check if input is a valid card number?
            #do we wanna check if output is a valid card number?
            #should card number length be 16, or should we allow other credit card formats as well?
        radix = 10
        msg = msg.replace(' ', '')
        print(msg)
        ciphertext = ''.join(encrypt_main(msg, T, key, radix))
        ciphertext = ciphertext[:4] + ' ' + ciphertext[4:8] + ' ' + ciphertext[8:12] + ' ' + ciphertext[12:16]
        print(ciphertext)
        return ciphertext

    if format == Format.LETTERS:
        #make lowercase or supper uppercase?
        radix = 26
        mapping = lettersDictE
        plainNumerals = map_from_numeral_string(msg,mapping)
        cipherNumerals = encrypt_main(plainNumerals,T,key,radix)
        ciphertext = ''.join(map_from_numeral_string(cipherNumerals,lettersDictD))
        print(ciphertext)

    if format == Format.STRING:
        #make lowercase or support uppercase?
        radix = 36
        mapping = stringDictE
        plainNumerals = map_from_numeral_string(msg,mapping)
        cipherNumerals = encrypt_main(plainNumerals,T,key,radix)
        ciphertext = ''.join(map_from_numeral_string(cipherNumerals,stringDictD))
        print(ciphertext)

    if format == Format.EMAIL:
        #check if email is valid?
        #check if cphtxt is valid?
        #split email into Recipient, Domain name, Top-level domain
        msg = msg.lower()
        domain=letters2+['@','.','!','#','$','£','%','&','\'','*','+','-','/','=','?','^','_','´','{','}','|']
        radix = len(domain)
        mapping = get_mapping_from_domain(domain)
        plainNumerals =  map_from_numeral_string(msg,mapping[0])
        cipherNumerals = encrypt_main(plainNumerals,T,key,radix)
        print(cipherNumerals)
        ciphertext = ''.join(map_from_numeral_string(cipherNumerals,mapping[1]))
        ciphertext = ciphertext[:(len(ciphertext)//2)] + '@' + ciphertext[(len(ciphertext)//2):]
        print(ciphertext)
        
    if format == Format.DATE:
        # do we wanna check if input is valid?
        # do we wanna check if output is valid?
        # should we split it up into day-month | year ?
        # what format do we wanna output? {dd/mm/yyyy, dd-mm-yyyy, dd/mm-yyyy, dd mm yyyy, dd.mm.yyyy, other?}
        radix = 10
        ciphertext = ''.join(encrypt_main(msg, T, key, radix))
        ciphertext = ciphertext[:2] + '.' + ciphertext[2:4] + '.' + ciphertext[4:]
        print(ciphertext)

    if format == Format.NAME:
        #change encrypt_main so it works?
        data = json.loads(open("names.json", "r").read())
        names = []
        #numbers = []
        for name in data['names']:
            names.append(name['name'])
            #numbers.append(name['number'])
        radix = len(names)
        mapping = get_mapping_from_domain(names)
        plainNumerals =  map_from_name(msg,mapping[0])
        cipherNumerals = encrypt_main(plainNumerals,T,key,radix)
        print(cipherNumerals)
        ciphertext = ''.join(map_from_name(cipherNumerals[0],mapping[1]))
        print(ciphertext)
    return ciphertext
    
def decrypt(msg,T,key,format):
    if format == Format.DIGITS:
        radix = 10
        plaintext = ''.join(decrypt_main(msg,T,key,radix))
        print(plaintext)

    if format == Format.CREDITCARD:
        radix = 10
        msg = msg.replace(' ', '')
        print(msg)
        plaintext = ''.join(decrypt_main(msg, T, key, radix))
        plaintext = plaintext[:4] + ' ' + plaintext[4:8] + ' ' + plaintext[8:12] + ' ' + plaintext[12:16]
        print(plaintext)

    if format == Format.LETTERS:
        radix = 26
        mapping = lettersDictE
        cipherNumerals = map_from_numeral_string(msg,mapping)
        plainNumerals = decrypt_main(cipherNumerals,T,key,radix)
        plaintext = ''.join(map_from_numeral_string(plainNumerals,lettersDictD))
        print(plaintext)

    if format == Format.STRING:
        radix = 36
        mapping = stringDictE
        cipherNumerals = map_from_numeral_string(msg,mapping)
        plainNumerals = decrypt_main(cipherNumerals,T,key,radix)
        plaintext = ''.join(map_from_numeral_string(plainNumerals,stringDictD))
        print(plaintext)

    if format == Format.EMAIL:        
        msg = msg[:((len((msg))-1)//2)] + msg[(((len(msg))-1)//2)+1:]
        domain=letters2+['@','.','!','#','$','£','%','&','\'','*','+','-','/','=','?','^','_','´','{','}','|']
        radix = len(domain)
        mapping = get_mapping_from_domain(domain)
        cipherNumerals = map_from_numeral_string(msg,mapping[0])
        plainNumerals = decrypt_main(cipherNumerals,T,key,radix)
        plaintext = ''.join(map_from_numeral_string(plainNumerals,mapping[1]))
        print(plaintext)

    if format == Format.DATE:
        msg = msg = msg[:2] + msg[3:5] + msg[6:10]
        radix = 10
        plaintext = ''.join(decrypt_main(msg,T,key,radix))
        plaintext = plaintext[:2] + '.' + plaintext[2:4] + '.' + plaintext[4:]
        print(plaintext)

    if format == Format.NAME:
        data = json.loads(open("names.json", "r").read())
        names = []
        #numbers = []
        for name in data['names']:
            names.append(name['name'])
            #numbers.append(name['number'])
        radix = len(names)
        mapping = get_mapping_from_domain(names)
        cipherNumerals = map_from_name(msg, mapping[0])
        plainNumerals = decrypt_main(cipherNumerals,T,key,radix)
        print(plainNumerals)
        plaintext = ''.join(map_from_name(plainNumerals[0],mapping[1]))
        print(plaintext)

    return plaintext

ciphertext = encrypt('1234567abcd8',T,key,Format.STRING)
decrypt(ciphertext,T,key,Format.STRING)
#print("--- %s seconds ---" % (time.time() - start_time))