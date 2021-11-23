import ff1
import ff3
import Mode
import Format
from format_translator import *
        
def encrypt(text,key,tweak,dataFormat,mode):
    if dataFormat == Format.EMAIL:
        plainNumerals =  text_to_numeral_list(text, Format.EMAIL)
        radixes = get_radix_by_format(Format.EMAIL)

        cipherNumerals = []

        if mode == Mode.FF1:
            cipherNumerals.append(ff1.encrypt(plainNumerals[0],key,tweak,radixes[0]))
            cipherNumerals.append(ff1.encrypt(plainNumerals[1],key,tweak,radixes[1]))
        elif mode == Mode.FF3:
            cipherNumerals.append(ff3.encrypt(plainNumerals[0],key,tweak,radixes[0]))
            cipherNumerals.append(ff3.encrypt(plainNumerals[1],key,tweak,radixes[1]))

        cipherNumerals.append(
                (plainNumerals[2] + 
                int(''.join([str(x) for x in plainNumerals[0]]) + 
                ''.join([str(x) for x in plainNumerals[1]]) +
                str(int.from_bytes(key,'big'))))%radixes[2])

        return numeral_list_to_text(cipherNumerals, Format.EMAIL)
        
    elif dataFormat == Format.CPR:
        plainNumerals = text_to_numeral_list(text, Format.CPR)
        radixes = get_radix_by_format(Format.CPR)

        cipherNumerals = []

        if mode == Mode.FF1:
            cipherNumerals.append(ff1.encrypt(plainNumerals[1],key,tweak,radixes[1]))
        elif mode == Mode.FF3:
            cipherNumerals.append(ff3.encrypt(plainNumerals[1],key,tweak,radixes[1]))
        
        cipherNumerals.append(
                (plainNumerals[0] + 
                int(''.join([str(x) for x in plainNumerals[1]]) + 
                str(int.from_bytes(key,'big'))))%radixes[0])

        return numeral_list_to_text(cipherNumerals, Format.CPR)

    else:
        plainNumerals = text_to_numeral_list(text, dataFormat)
        radix = get_radix_by_format(dataFormat)

        if mode == Mode.FF1:
            cipherNumerals = ff1.encrypt(plainNumerals,key,tweak,radix)
        elif mode == Mode.FF3:
            cipherNumerals = ff3.encrypt(plainNumerals,key,tweak,radix)
        return numeral_list_to_text(cipherNumerals, dataFormat)

def decrypt(text,key,tweak,dataFormat,mode):
    if dataFormat == Format.EMAIL:
        cipherNumerals = text_to_numeral_list(text, Format.EMAIL)
        radixes = get_radix_by_format(Format.EMAIL)

        plainNumerals = []

        if mode == Mode.FF1:
            plainNumerals.append(ff1.decrypt(cipherNumerals[0],key,tweak,radixes[0]))
            plainNumerals.append(ff1.decrypt(cipherNumerals[1],key,tweak,radixes[1]))
        elif mode == Mode.FF3:
            plainNumerals.append(ff3.decrypt(cipherNumerals[0],key,tweak,radixes[0]))
            plainNumerals.append(ff3.decrypt(cipherNumerals[1],key,tweak,radixes[1]))
        
        plainNumerals.append(
                (cipherNumerals[2] - 
                int(''.join([str(x) for x in plainNumerals[0]]) + 
                ''.join([str(x) for x in plainNumerals[1]]) +
                str(int.from_bytes(key,'big'))))%radixes[2])

        return numeral_list_to_text(plainNumerals, Format.EMAIL)
        
    elif dataFormat == Format.CPR:
        cipherNumerals = text_to_numeral_list(text, Format.CPR)
        radixes = get_radix_by_format(Format.CPR)

        plainNumerals = []

        if mode == Mode.FF1:
            plainNumerals.append(ff1.decrypt(cipherNumerals[1],key,tweak,radixes[1]))
        elif mode == Mode.FF3:
            plainNumerals.append(ff3.decrypt(cipherNumerals[1],key,tweak,radixes[1]))

        plainNumerals.append(
                (cipherNumerals[0] - 
                int(''.join([str(x) for x in plainNumerals[0]]) + 
                str(int.from_bytes(key,'big'))))%radixes[0])
        return numeral_list_to_text(plainNumerals, Format.CPR)

    else:
        radix = get_radix_by_format(dataFormat)
        plainNumerals = text_to_numeral_list(text, dataFormat)

        if mode == Mode.FF1:
            cipherNumerals = ff1.decrypt(plainNumerals,key,tweak,radix)
        elif mode == Mode.FF3: 
            cipherNumerals = ff3.decrypt(plainNumerals,key,tweak,radix)

        return numeral_list_to_text(cipherNumerals, dataFormat)
