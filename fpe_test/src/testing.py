import ff11
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

T = bytes.fromhex('3737373770717273373737')
key = bytes.fromhex('2B7E151628AED2A6ABF7158809CF4F3C')
cipher = AES.new(key, AES.MODE_ECB)

def encrypt(msg, T, key, format):
    cipher = AES.new(key, AES.MODE_ECB)

    if format == Format.DIGITS:
        radix = 10
        ciphertext = ''.join(ff11.encrypt(msg, T, key, radix,cipher))
        return ciphertext

    if format == Format.CREDITCARD:
        # how much in depth do we wanna go?
        # should we check other parameters than checkSum?
        # should card number length be 16, or should we allow other credit card formats as well?
        msg = msg.replace(' ', '')
        if (msg[len(msg) - 1] != validateCard(msg[:len(msg) - 1])):
            raise ValueError(f"{msg} is not a valid credit card number")
        radix = 10
        ciphertext = ''.join(ff11.encrypt(msg[:len(msg) - 1], T, key, radix,cipher))
        ciphertext = ciphertext[:4] + ' ' + ciphertext[4:8] + ' ' + ciphertext[8:12] + ' ' + ciphertext[12:] + validateCard(ciphertext)

    if format == Format.LETTERS:
        radix = len(mapping_letters[0])
        mapping = mapping_letters
        plainNumerals = map_from_numeral_string(msg, mapping[0])
        cipherNumerals = ff11.encrypt(plainNumerals, T, key, radix,cipher)
        ciphertext = ''.join(map_from_numeral_string(cipherNumerals, mapping[1]))

    if format == Format.STRING:
        mapping = mapping_all
        radix = len(mapping[0])
        plainNumerals = map_from_numeral_string(msg, mapping[0])
        cipherNumerals = ff11.encrypt(plainNumerals, T, key, radix,cipher)
        ciphertext = ''.join(map_from_numeral_string(cipherNumerals, mapping[1]))
        
    if format == Format.EMAIL:
        # check if email is valid?
        # check if cphtxt is valid?
        # split email into Recipient, Domain name, Top-level domain?
        # create random length?
        msg = msg.lower()
        first_break_index = msg.find('@')
        second_break_index = msg.rfind('.')
        msg1 = msg[:first_break_index]
        msg2 = msg[first_break_index+1:second_break_index]
        msg3 = msg[second_break_index+1:]
        mapping1 = mapping_all
        mapping2 = mapping_email_tail
        mapping3 = mapping_top_lvl_domains
        radix1 = len(mapping1[0])
        radix2 = len(mapping2[0])
        radix3 = len(mapping3[0])
        plainNumerals1 =  map_from_numeral_string(msg1,mapping1[0])
        plainNumerals2 =  map_from_numeral_string(msg2,mapping2[0])
        plainNumerals3 =  map_from_name(msg3,mapping3[0])
        cipherNumerals1 = ff11.encrypt(plainNumerals1,T,key,radix1,cipher)
        cipherNumerals2 = ff11.encrypt(plainNumerals2,T,key,radix2,cipher)
        cipherNumerals3 = str((int(plainNumerals3) + int(''.join(plainNumerals1)) + int(''.join(plainNumerals2)) + int.from_bytes(key,'big'))%radix3)
        ciphertext1 = ''.join(map_from_numeral_string(cipherNumerals1,mapping1[1]))
        ciphertext2 = ''.join(map_from_numeral_string(cipherNumerals2,mapping2[1]))
        ciphertext3 = ''.join(map_from_name(cipherNumerals3,mapping3[1]))
        ciphertext = ciphertext1 + '@' + ciphertext2 + '.' + ciphertext3
        
    if format == Format.DATE:
        # do we wanna check if input is valid?
        # do we wanna check if output is valid?
        # should we split it up into day-month | year ?
        # what format do we wanna output? {dd/mm/yyyy, dd-mm-yyyy, dd/mm-yyyy, dd mm yyyy, dd.mm.yyyy, other?}
        clean_msg = sub(r"\D", "", msg)
        radix = 10
        ciphertext = ''.join(ff11.encrypt(clean_msg, T, key, radix,cipher))
        ciphertext = ciphertext[:2] + '.' + ciphertext[2:4] + '.' + ciphertext[4:]
        #we can use our msg to keep the format insted of just creating our own format.. maybe somehow
        
    if format == Format.NAME:
        mapping = mapping_name
        radix = len(mapping_name[0])
        plainNumerals = map_from_name(msg, mapping[0])
        cipherNumerals = ff11.encrypt(plainNumerals, T, key, radix,cipher)
        ciphertext = ''.join(map_from_name(cipherNumerals, mapping[1]))
        # insert ciphernumerals[0] above to make it runnable
        
    if format == Format.CPR:
        if (msg[len(msg) - 1] != validateCPR(msg[:len(msg) - 1])):
            raise ValueError(f"{msg} is not a valid CPR number")
        mapping = mapping_dates
        radix1 = 10
        radix2 = len(mapping[0])
        msg1 = msg[:4]
        msg2 = [int(x) for x in msg[4:9]]
        plainNumerals = map_from_name(msg1,mapping[0])
        cipherNumerals = ff11.encrypt(msg2, T, key, radix1,cipher)
        ciphertext1 = "".join([str(x) for x in cipherNumerals])
        ciphertext2 = map_from_name(((int(plainNumerals) + (int(msg[4:9]) + int.from_bytes(key,'big'))) % radix2),mapping[1])
        ciphertext = ciphertext2 + ciphertext1
        ciphertext = ciphertext + validateCPR(ciphertext)
        

    return ciphertext


def decrypt(msg, T, key, format):
    cipher = AES.new(key, AES.MODE_ECB)

    if format == Format.DIGITS:
        radix = 10
        plaintext = ''.join(ff11.decrypt(msg, T, key, radix,cipher))

    if format == Format.CREDITCARD:
        msg = msg.replace(' ', '')
        if (msg[len(msg) - 1] != validateCard(msg[:len(msg) - 1])):
            raise ValueError(f"{msg} is not a valid credit card number")
        radix = 10
        plaintext = ''.join(ff11.decrypt(msg[:len(msg) - 1], T, key, radix,cipher))
        plaintext = plaintext[:4] + ' ' + plaintext[4:8] + ' ' + plaintext[8:12] + ' ' + plaintext[12:] + validateCard(plaintext)
        
    if format == Format.LETTERS:
        mapping = mapping_letters
        radix = len(mapping[0])
        cipherNumerals = map_from_numeral_string(msg, mapping[0])
        plainNumerals = ff11.decrypt(cipherNumerals, T, key, radix,cipher)
        plaintext = ''.join(map_from_numeral_string(plainNumerals, mapping[1]))
        
    if format == Format.STRING:
        mapping = mapping_letters_integer
        radix = len(mapping[0])
        cipherNumerals = map_from_numeral_string(msg, mapping[0])
        plainNumerals = ff11.decrypt(cipherNumerals, T, key, radix,cipher)
        plaintext = ''.join(map_from_numeral_string(plainNumerals, mapping[1]))
        
    if format == Format.EMAIL:  
        
        first_break_index = msg.find('@')
        second_break_index = msg.rfind('.')

        msg1 =msg[:first_break_index]
        msg2 = msg[first_break_index+1:second_break_index]
        msg3 = msg[second_break_index+1:]
        mapping1 = mapping_all
        mapping2 = mapping_email_tail
        mapping3 = mapping_top_lvl_domains
        radix1 = len(mapping1[0])
        radix2 = len(mapping2[0])
        radix3 = len(mapping3[0])

        cipherNumerals1 =  map_from_numeral_string(msg1,mapping1[0])
        cipherNumerals2 =  map_from_numeral_string(msg2,mapping2[0])
        cipherNumerals3 =  map_from_name(msg3,mapping3[0])
        plainNumerals1 = ff11.decrypt(cipherNumerals1,T,key,radix1,cipher)
        plainNumerals2 = ff11.decrypt(cipherNumerals2,T,key,radix2,cipher)
        plainNumerals3 = str((int(cipherNumerals3) - int(''.join(plainNumerals1) + ''.join(plainNumerals2 + int.from_bytes(key,'big'))))%radix3)
        plaintext1 = ''.join(map_from_numeral_string(plainNumerals1,mapping1[1]))
        plaintext2 = ''.join(map_from_numeral_string(plainNumerals2,mapping2[1]))
        plaintext3 = ''.join(map_from_name(plainNumerals3,mapping3[1]))
        plaintext = plaintext1 + '@' + plaintext2 + '.' + plaintext3
        
    if format == Format.DATE:
        clean_msg = sub(r"\D", "", msg)
        radix = 10
        plaintext = ''.join(ff11.decrypt(clean_msg, T, key, radix,cipher))
        plaintext = plaintext[:2] + '.' + plaintext[2:4] + '.' + plaintext[4:]
        
    if format == Format.NAME:
        mapping = mapping_name
        radix = len(mapping_name[0])
        cipherNumerals = map_from_name(msg, mapping[0])
        plainNumerals = ff11.decrypt(cipherNumerals, T, key, radix,cipher)
        plaintext = ''.join(map_from_name(plainNumerals, mapping[1]))
        # insert plainnumerals[0] above to make it runnable
        
    if format == Format.CPR:
        if (msg[len(msg) - 1] != validateCPR(msg[:len(msg) - 1])):
            raise ValueError(f"{msg} is not a valid CPR number")
        mapping = mapping_dates
        radix1 = 10
        radix2 = len(mapping[0])
        msg1 = msg[:4]
        msg2 = [int(x) for x in msg[4:9]]
        cipherNumerals = map_from_name(msg1,mapping[0])
        plainNumerals = ff11.decrypt(msg2, T, key, radix1,cipher)
        plaintext1 = "".join([str(x) for x in plainNumerals])
        plaintext2 = map_from_name((int(cipherNumerals) - (int(plaintext1) + int.from_bytes(key,'big'))) % radix2,mapping[1])
        plaintext = plaintext2 + plaintext1
        plaintext = plaintext + validateCPR(plaintext)
        
    return plaintext


for _ in range(1):
    ciphertext = encrypt('hello', T, key, Format.LETTERS)
    decrypt(ciphertext,T,key,Format.LETTERS)
print("--- %s seconds ---" % (time.time() - start_time))