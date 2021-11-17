import ff1
import ff3
from utils import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from format_translator import *

FORMAT_DIGITS = 0
FORMAT_CREDITCARD = 1
FORMAT_LETTERS = 2
FORMAT_STRING = 3
FORMAT_EMAIL = 4
FORMAT_CPR = 5
MODE_FF1 = 6
MODE_FF3 = 7

def generate_tweak(length):
    return get_random_bytes(length)

def generate_key():
    return get_random_bytes(16)

class New:
    def __init__(self, key, tweak, mode):
        self.key = key
        self.tweak = tweak
        self.mode = mode
        if mode == MODE_FF3:
            self.key = reverse(key)
        self.cipher = AES.new(key, AES.MODE_ECB)

    def set_key(self,key):
        self.key = key
        self.cipher = AES.new(key, AES.MODE_ECB)
        
    def encrypt(self,text,dataFormat):
        if dataFormat == FORMAT_EMAIL:
            plainNumerals =  text_to_numeral_list(text, FORMAT_EMAIL)

            radixes = get_radix_by_format(FORMAT_EMAIL)

            cipherNumerals = []

            if self.mode == MODE_FF1:
                cipherNumerals.append(ff1.encrypt(plainNumerals[0],self.tweak,radixes[0],self.cipher))
                cipherNumerals.append(ff1.encrypt(plainNumerals[1],self.tweak,radixes[1],self.cipher))
            elif self.mode == MODE_FF3:
                cipherNumerals.append(ff3.encrypt(plainNumerals[0],self.tweak,radixes[0],self.cipher))
                cipherNumerals.append(ff3.encrypt(plainNumerals[1],self.tweak,radixes[1],self.cipher))

            cipherNumerals.append(
                    (plainNumerals[2] + 
                    int(''.join([str(x) for x in plainNumerals[0]]) + 
                    ''.join([str(x) for x in plainNumerals[1]]) +
                    str(int.from_bytes(self.key,'big'))))%radixes[2])

            return numeral_list_to_text(cipherNumerals, FORMAT_EMAIL)
            
        elif dataFormat == Format.CPR:
            radixes = get_radix_by_format(Format.CPR)
            plainNumerals = text_to_numeral_list(text, Format.CPR)

            cipherNumerals = []

            if self.mode == MODE_FF1:
                cipherNumerals.append(ff1.encrypt(plainNumerals[1],self.tweak,radixes[1],self.cipher))
            elif self.mode == MODE_FF3:
                cipherNumerals.append(ff3.encrypt(plainNumerals[1],self.tweak,radixes[1],self.cipher))
            
            cipherNumerals.append(
                    (plainNumerals[0] + 
                    int(''.join([str(x) for x in plainNumerals[1]]) + 
                    str(int.from_bytes(self.key,'big'))))%radixes[0])

            return numeral_list_to_text(cipherNumerals, Format.CPR)

        else:
            radix = get_radix_by_format(dataFormat)
            plainNumerals = text_to_numeral_list(text, dataFormat)
            if self.mode == MODE_FF1:
                cipherNumerals = ff1.encrypt(plainNumerals,self.tweak,radix,self.cipher)
            elif self.mode == MODE_FF3:
                cipherNumerals = ff3.encrypt(plainNumerals,self.tweak,radix,self.cipher)
            return numeral_list_to_text(cipherNumerals, dataFormat)

    def decrypt(self,text,dataFormat):
        if dataFormat == FORMAT_EMAIL:
            cipherNumerals = text_to_numeral_list(text, FORMAT_EMAIL)

            radixes = get_radix_by_format(FORMAT_EMAIL)

            plainNumerals = []

            if self.mode == MODE_FF1:
                plainNumerals.append(ff1.decrypt(cipherNumerals[0],self.tweak,radixes[0],self.cipher))
                plainNumerals.append(ff1.decrypt(cipherNumerals[1],self.tweak,radixes[1],self.cipher))
            elif self.mode == MODE_FF3:
                plainNumerals.append(ff3.decrypt(cipherNumerals[0],self.tweak,radixes[0],self.cipher))
                plainNumerals.append(ff3.decrypt(cipherNumerals[1],self.tweak,radixes[1],self.cipher))
            
            plainNumerals.append(
                    (cipherNumerals[2] - 
                    int(''.join([str(x) for x in plainNumerals[0]]) + 
                    ''.join([str(x) for x in plainNumerals[1]]) +
                    str(int.from_bytes(self.key,'big'))))%radixes[2])

            return numeral_list_to_text(plainNumerals, FORMAT_EMAIL)
            
        elif dataFormat == Format.CPR:
            radixes = get_radix_by_format(Format.CPR)
            cipherNumerals = text_to_numeral_list(text, Format.CPR)

            plainNumerals = []

            if self.mode == MODE_FF1:
                plainNumerals.append(ff1.decrypt(cipherNumerals[1],self.tweak,radixes[1],self.cipher))
            elif self.mode == MODE_FF3:
                plainNumerals.append(ff3.decrypt(cipherNumerals[1],self.tweak,radixes[1],self.cipher))

            plainNumerals.append(
                    (cipherNumerals[0] - 
                    int(''.join([str(x) for x in plainNumerals[0]]) + 
                    str(int.from_bytes(self.key,'big'))))%radixes[0])
            return numeral_list_to_text(plainNumerals, Format.CPR)

        else:
            radix = get_radix_by_format(dataFormat)
            plainNumerals = text_to_numeral_list(text, dataFormat)
            if self.mode == MODE_FF1:
                cipherNumerals = ff1.decrypt(plainNumerals,self.tweak,radix,self.cipher)
            elif self.mode == MODE_FF3: 
                cipherNumerals = ff3.decrypt(plainNumerals,self.tweak,radix,self.cipher)

            return numeral_list_to_text(cipherNumerals, dataFormat)
