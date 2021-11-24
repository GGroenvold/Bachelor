import mode_selector
from format_translator import Format,text_to_numeral_list,numeral_list_to_text,get_radix_by_format
        
def encrypt(text,key,tweak,dataFormat,mode):
    if dataFormat == Format.EMAIL:
        plainNumerals =  text_to_numeral_list(text, dataFormat)
        radixes = get_radix_by_format(dataFormat)

        cipherNumerals = []

        cipherNumerals.append(mode_selector.encrypt(plainNumerals[0],key,tweak,radixes[0],mode))
        cipherNumerals.append(mode_selector.encrypt(plainNumerals[1],key,tweak,radixes[1],mode))
                        
        cipherNumerals.append(
                (plainNumerals[2] + 
                int(''.join([str(x) for x in plainNumerals[0]]) + 
                ''.join([str(x) for x in plainNumerals[1]]) +
                str(int.from_bytes(key,'big'))))%radixes[2])

        return numeral_list_to_text(cipherNumerals, dataFormat)
        
    elif dataFormat == Format.CPR:
        plainNumerals = text_to_numeral_list(text, dataFormat)
        radixes = get_radix_by_format(dataFormat)

        cipherNumerals = []

        
        cipherNumerals.append(mode_selector.encrypt(plainNumerals[1],key,tweak,radixes[1],mode))
        
        cipherNumerals.append(
                (plainNumerals[0] + 
                int(''.join([str(x) for x in plainNumerals[1]]) + 
                str(int.from_bytes(key,'big'))))%radixes[0])

        return numeral_list_to_text(cipherNumerals, dataFormat)

    else:
        plainNumerals = text_to_numeral_list(text, dataFormat)
        radix = get_radix_by_format(dataFormat)

        
        cipherNumerals = mode_selector.encrypt(plainNumerals,key,tweak,radix,mode)
        
        return numeral_list_to_text(cipherNumerals, dataFormat)

def decrypt(text,key,tweak,dataFormat,mode):
    if dataFormat == Format.EMAIL:
        cipherNumerals = text_to_numeral_list(text, dataFormat)
        radixes = get_radix_by_format(dataFormat)

        plainNumerals = []

        plainNumerals.append(mode_selector.decrypt(cipherNumerals[0],key,tweak,radixes[0],mode))
        plainNumerals.append(mode_selector.decrypt(cipherNumerals[1],key,tweak,radixes[1],mode))
        
        plainNumerals.append(
                (cipherNumerals[2] - 
                int(''.join([str(x) for x in plainNumerals[0]]) + 
                ''.join([str(x) for x in plainNumerals[1]]) +
                str(int.from_bytes(key,'big'))))%radixes[2])

        return numeral_list_to_text(plainNumerals, dataFormat)
        
    elif dataFormat == Format.CPR:
        cipherNumerals = text_to_numeral_list(text, dataFormat)
        radixes = get_radix_by_format(dataFormat)

        plainNumerals = []

        plainNumerals.append(mode_selector.decrypt(cipherNumerals[1],key,tweak,radixes[1],mode))

        plainNumerals.append(
                (cipherNumerals[0] - 
                int(''.join([str(x) for x in plainNumerals[0]]) + 
                str(int.from_bytes(key,'big'))))%radixes[0])
        return numeral_list_to_text(plainNumerals, dataFormat)

    else:
        radix = get_radix_by_format(dataFormat)
        plainNumerals = text_to_numeral_list(text, dataFormat)


        cipherNumerals = mode_selector.decrypt(plainNumerals,key,tweak,radix,mode)

        return numeral_list_to_text(cipherNumerals, dataFormat)
