#Ceil function
import math
from utils import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from enum import Enum, auto
import time
import binascii
import json

start_time = time.time()

class Format(Enum):
    DIGITS = auto()
    CREDITCARD = auto()
    LETTERS = auto()
    STRING = auto()
    EMAIL = auto()
    DATE = auto()
    NAME = auto()

data = json.loads(open("names.json", "r").read())
names = []
for name in data['names']:
    names.append(name['name'])

domain = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
          'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
          '0','1','2','3','4','5','6','7','8','9',
          '.','-','!','#','$','£','%','&','\'','*','+','/','=','?','^','_','´','{','}','|']
lower_letter_index = 0
upper_letter_index = 26
integer_index = 52
special_signs_index = 62

mapping_letters = get_mapping_from_domain(domain[:integer_index])
mapping_upper_letters = get_mapping_from_domain(domain[upper_letter_index:integer_index])
mapping_lower_letters = get_mapping_from_domain(domain[:upper_letter_index])
mapping_email_tail = get_mapping_from_domain(domain[:upper_letter_index]+domain[integer_index:special_signs_index+2])
mapping_letters_integer = get_mapping_from_domain(domain[:special_signs_index])
mapping_all = get_mapping_from_domain(domain)
mapping_name = get_mapping_from_domain(names)

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
            #should we check other parameters than checkSum?
            #should card number length be 16, or should we allow other credit card formats as well?
        msg = msg.replace(' ', '')
        if (msg[len(msg)-1]!=validateCard(msg[:len(msg)-1])):    
            raise ValueError(f"{msg} is not a valid credit card number")
        radix = 10
        ciphertext = ''.join(encrypt_main(msg[:len(msg)-1], T, key, radix))
        ciphertext = ciphertext[:4] + ' ' + ciphertext[4:8] + ' ' + ciphertext[8:12] + ' ' + ciphertext[12:] + validateCard(ciphertext)
        print(ciphertext)
        return ciphertext

    if format == Format.LETTERS:
        radix = len(mapping_letters)
        mapping = mapping_letters
        plainNumerals = map_from_numeral_string(msg,mapping[0])
        cipherNumerals = encrypt_main(plainNumerals,T,key,radix)
        ciphertext = ''.join(map_from_numeral_string(cipherNumerals,mapping[1]))
        print(ciphertext)

    if format == Format.STRING:
        mapping = mapping_letters_integer
        radix = len(mapping[0])
        plainNumerals = map_from_numeral_string(msg,mapping[0])
        cipherNumerals = encrypt_main(plainNumerals,T,key,radix)
        ciphertext = ''.join(map_from_numeral_string(cipherNumerals,mapping[1]))
        print(ciphertext)

    if format == Format.EMAIL:
        #check if email is valid?
        #check if cphtxt is valid?
        #split email into Recipient, Domain name, Top-level domain?
        #create random length?
        msg = msg.lower()
        break_index = msg.find('@')
        msg1 =msg[:break_index]
        msg2 =msg[break_index+1:]
        mapping1 = mapping_all
        mapping2 = mapping_email_tail
        radix1 = len(mapping1[0])
        radix2 = len(mapping2[0])

        plainNumerals1 =  map_from_numeral_string(msg1,mapping1[0])
        plainNumerals2 =  map_from_numeral_string(msg2,mapping2[0])
        cipherNumerals1 = encrypt_main(plainNumerals1,T,key,radix1)
        cipherNumerals2 = encrypt_main(plainNumerals2,T,key,radix2)
        print(cipherNumerals1)
        print(cipherNumerals2)
        ciphertext1 = ''.join(map_from_numeral_string(cipherNumerals1,mapping1[1]))
        ciphertext2 = ''.join(map_from_numeral_string(cipherNumerals2,mapping2[1]))
        ciphertext = ciphertext1 + '@' + ciphertext2
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
        mapping = mapping_name
        radix = len(mapping_name[0])
        plainNumerals = map_from_name(msg,mapping[0])
        cipherNumerals = encrypt_main(plainNumerals,T,key,radix)
        ciphertext = ''.join(map_from_name(cipherNumerals,mapping[1]))
        #insert ciphernumerals[0] above to make it runnable
        print(ciphertext)
        
    return ciphertext
    
def decrypt(msg,T,key,format):
    if format == Format.DIGITS:
        radix = 10
        plaintext = ''.join(decrypt_main(msg,T,key,radix))
        print(plaintext)

    if format == Format.CREDITCARD:
        msg = msg.replace(' ', '')
        if (msg[len(msg)-1]!=validateCard(msg[:len(msg)-1])):    
            raise ValueError(f"{msg} is not a valid credit card number")
        radix = 10
        plaintext = ''.join(decrypt_main(msg[:len(msg)-1], T, key, radix))
        plaintext = plaintext[:4] + ' ' + plaintext[4:8] + ' ' + plaintext[8:12] + ' ' + plaintext[12:] + validateCard(plaintext)
        print(plaintext)

    if format == Format.LETTERS:
        mapping = mapping_letters
        radix = len(mapping[0])
        cipherNumerals = map_from_numeral_string(msg,mapping[0])
        plainNumerals = decrypt_main(cipherNumerals,T,key,radix)
        plaintext = ''.join(map_from_numeral_string(plainNumerals,mapping[1]))
        print(plaintext)

    if format == Format.STRING:
        mapping = mapping_letters_integers
        radix = len(mapping[0])
        cipherNumerals = map_from_numeral_string(msg,mapping[0])
        plainNumerals = decrypt_main(cipherNumerals,T,key,radix)
        plaintext = ''.join(map_from_numeral_string(plainNumerals,mapping[1]))
        print(plaintext)

    if format == Format.EMAIL:        
        break_index = msg.find('@')
        msg1 =msg[:break_index]
        msg2 =msg[break_index+1:]
        mapping1 = mapping_all
        mapping2 = mapping_email_tail
        radix1 = len(mapping1[0])
        radix2 = len(mapping2[0])

        cipherNumerals1 =  map_from_numeral_string(msg1,mapping1[0])
        cipherNumerals2 =  map_from_numeral_string(msg2,mapping2[0])
        plainNumerals1 = decrypt_main(cipherNumerals1,T,key,radix1)
        plainNumerals2 = decrypt_main(cipherNumerals2,T,key,radix2)
        plaintext1 = ''.join(map_from_numeral_string(plainNumerals1,mapping1[1]))
        plaintext2 = ''.join(map_from_numeral_string(plainNumerals2,mapping2[1]))
        plaintext = plaintext1 + '@' + plaintext2
        print(plaintext)

    if format == Format.DATE:
        msg = msg = msg[:2] + msg[3:5] + msg[6:10]
        radix = 10
        plaintext = ''.join(decrypt_main(msg,T,key,radix))
        plaintext = plaintext[:2] + '.' + plaintext[2:4] + '.' + plaintext[4:]
        print(plaintext)

    if format == Format.NAME:
        mapping = mapping_name
        radix = len(mapping_name[0])
        cipherNumerals =  map_from_name(msg,mapping[0])
        plainNumerals = decrypt_main(cipherNumerals,T,key,radix)
        plaintext = ''.join(map_from_name(plainNumerals,mapping[1]))
        #insert plainnumerals[0] above to make it runnable
        print(plaintext)

    return plaintext
ciphertext = encrypt('4012888888881881',T,key,Format.CREDITCARD)
decrypt(ciphertext,T,key,Format.CREDITCARD)
#print("--- %s seconds ---" % (time.time() - start_time))