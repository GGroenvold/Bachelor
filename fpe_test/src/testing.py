import ff11
import ff3_cy as ff3
import math
from utils import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from enum import Enum, auto
from re import sub
import time
import binascii
from format_translator import *

start_time = time.time()

T = bytes.fromhex('D8E7920AFA330A')
key = reverse(bytes.fromhex('EF4359D8D580AA4F7F036D6F04FC6A94'))
cipher = AES.new(key, AES.MODE_ECB)

def encrypt(text, T,dataFormat):
    cipher = AES.new(key, AES.MODE_ECB)

    if dataFormat == Format.EMAIL:
        plainNumerals =  text_to_numeral_list(text, Format.EMAIL)

        radixes = get_radix_by_format(Format.EMAIL)

        cipherNumerals = []

        cipherNumerals.append(ff11.encrypt(plainNumerals[0],T,radixes[0],cipher))
        cipherNumerals.append(ff11.encrypt(plainNumerals[1],T,radixes[1],cipher))
        cipherNumerals.append(
                (plainNumerals[2] + 
                int(''.join([str(x) for x in plainNumerals[0]]) + 
                ''.join([str(x) for x in plainNumerals[1]]) +
                str(int.from_bytes(key,'big'))))%radixes[2])

        return numeral_list_to_text(cipherNumerals, Format.EMAIL)
        
    elif dataFormat == Format.CPR:
        radixes = get_radix_by_format(Format.CPR)
        plainNumerals = text_to_numeral_list(text, Format.CPR)

        cipherNumerals = []
        cipherNumerals.append(ff3.encrypt(plainNumerals[1],T,radixes[1],cipher))
        cipherNumerals.append(
                (plainNumerals[0] + 
                int(''.join([str(x) for x in plainNumerals[1]]) + 
                str(int.from_bytes(key,'big'))))%radixes[0])

        return numeral_list_to_text(cipherNumerals, Format.CPR)

    else:
        radix = get_radix_by_format(dataFormat)
        plainNumerals = text_to_numeral_list(text, dataFormat)
        cipherNumerals = ff3.encrypt(plainNumerals,T,radix,cipher)
        
        return numeral_list_to_text(cipherNumerals, dataFormat)

def decrypt(text, T,dataFormat):
    cipher = AES.new(key, AES.MODE_ECB)

    if dataFormat == Format.EMAIL:
        cipherNumerals = text_to_numeral_list(text, Format.EMAIL)

        radixes = get_radix_by_format(Format.EMAIL)

        plainNumerals = []

        plainNumerals.append(ff11.decrypt(cipherNumerals[0],T,radixes[0],cipher))
        plainNumerals.append(ff11.decrypt(cipherNumerals[1],T,radixes[1],cipher))
        plainNumerals.append(
                (cipherNumerals[2] - 
                int(''.join([str(x) for x in plainNumerals[0]]) + 
                ''.join([str(x) for x in plainNumerals[1]]) +
                str(int.from_bytes(key,'big'))))%radixes[2])

        return numeral_list_to_text(plainNumerals, Format.EMAIL)
        
    elif dataFormat == Format.CPR:
        radixes = get_radix_by_format(Format.CPR)
        cipherNumerals = text_to_numeral_list(text, Format.CPR)

        plainNumerals = []

        plainNumerals.append(ff3.decrypt(cipherNumerals[1],T,radixes[1],cipher))
        plainNumerals.append(
                (cipherNumerals[0] - 
                int(''.join([str(x) for x in plainNumerals[0]]) + 
                str(int.from_bytes(key,'big'))))%radixes[0])
        return numeral_list_to_text(plainNumerals, Format.CPR)

    else:
        radix = get_radix_by_format(dataFormat)
        plainNumerals = text_to_numeral_list(text, dataFormat)
        cipherNumerals = ff3.decrypt(plainNumerals,T,radix,cipher)
         
        return numeral_list_to_text(cipherNumerals, dataFormat)


for _ in range(1):
    ciphertext = encrypt('example@email.com',T,Format.EMAIL)
    print(ciphertext)
    print(decrypt(ciphertext,T,Format.EMAIL))
print("--- %s seconds ---" % (time.time() - start_time))
