from utils import *
import Format
import json

RADIX_DEFAULT = 10

data = json.loads(open("src/Lars_er_sej/dates.json", "r").read())
dates = []
for i in data['dates']:
    dates.append(i['date'])
    
data = json.loads(open("src/Lars_er_sej/top-lvl-domains.json", "r").read())
top_lvl_domains = []
for top_lvl_domain in data['top-lvl-domains']:
    top_lvl_domains.append(top_lvl_domain['top-lvl-domain'])
    
DOMAIN = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','æ','ø','å',
          'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','Æ','Ø','Å',
          '0','1','2','3','4','5','6','7','8','9',
          '.','-','!','#','$','£','%','&','\'','*','+','/','=','?','^','_','´','{','}','|',' ',',','(',')',':','<','>','`','~','é']
LOWER_LETTER_END = 29
UPPER_LETTER_END = 58
INTEGER_END = 68
EMAIL_SIGNS_END = 85

mapping_letters = get_mapping_from_domain(DOMAIN[:UPPER_LETTER_END])
mapping_upper_letters = get_mapping_from_domain(DOMAIN[LOWER_LETTER_END:UPPER_LETTER_END])
mapping_lower_letters = get_mapping_from_domain(DOMAIN[:LOWER_LETTER_END])
mapping_email_tail = get_mapping_from_domain(DOMAIN[:INTEGER_END+2])
mapping_letters_integer = get_mapping_from_domain(DOMAIN[:INTEGER_END])
mapping_all = get_mapping_from_domain(DOMAIN)
mapping_dates = get_mapping_from_domain(dates)
mapping_top_lvl_domains = get_mapping_from_domain(top_lvl_domains)


def text_to_numeral_list(text, dataFormat):
    if dataFormat == Format.DIGITS:
        return [int(x) for x in text]

    if dataFormat == Format.CREDITCARD:
        text = text.replace(' ', '')

        if (text[len(text) - 1] != validateCard(text[:len(text) - 1])):
            raise ValueError(f"{text} is not a valid credit card number")

        return [int(x) for x in text[:len(text)-1]]

    if dataFormat == Format.LETTERS:

        return map_from_numeral_string(text, mapping_letters[0])

    if dataFormat == Format.STRING:
        numerals = map_from_numeral_string(text, mapping_all[0])
        
        return numerals
        
    if dataFormat == Format.EMAIL:
        first_break_index = text.find('@')
        second_break_index = text.rfind('.')

        text1 = text[:first_break_index]
        text2 = text[first_break_index+1:second_break_index]
        text3 = text[second_break_index+1:]

        numerals1 =  map_from_numeral_string(text1,mapping_letters_integer[0])
        numerals2 =  map_from_numeral_string(text2,mapping_email_tail[0])
        numerals3 =  map_from_name(text3,mapping_top_lvl_domains[0])

        return [numerals1, numerals2, numerals3] 

    if dataFormat == Format.CPR:
        if (text[len(text) - 1] != validateCPR(text[:len(text) - 1])):
            raise ValueError(f"{text} is not a valid CPR number")

        text1 = text[:4]

        numerals1 = map_from_name(text1,mapping_dates[0])
        numerals2 = [int(x) for x in text[4:9]]

        return [numerals1, numerals2]


def numeral_list_to_text(numerals, dataFormat):
    if dataFormat == Format.DIGITS:
        return ''.join([str(x) for x in numerals])

    if dataFormat == Format.CREDITCARD:
        text1 = ''.join([str(x) for x in numerals[:4]])
        text2 = ''.join([str(x) for x in numerals[4:8]])
        text3 = ''.join([str(x) for x in numerals[8:12]])
        text4 = ''.join([str(x) for x in numerals[12:]])

        return text1 + ' ' + text2 + ' ' + text3 + ' ' + text4 + validateCard(text1+text2+text3+text4)

    if dataFormat == Format.LETTERS:
        return ''.join(map_from_numeral_string(numerals, mapping_letters[1]))

    if dataFormat == Format.STRING:
        return ''.join(map_from_numeral_string(numerals, mapping_all[1]))
        
    if dataFormat == Format.EMAIL:
        text1 = ''.join(map_from_numeral_string(numerals[0],mapping_letters_integer[1]))
        text2 = ''.join(map_from_numeral_string(numerals[1],mapping_email_tail[1]))
        text3 = ''.join(map_from_name(numerals[2],mapping_top_lvl_domains[1]))

        return text1 + '@' + text2 + '.' + text3
        
    if dataFormat == Format.CPR:
        text1 = ''.join(map_from_name(numerals[1],mapping_dates[1]))
        text2 = ''.join([str(x) for x in numerals[0]])

        return text1 + text2 + validateCPR(text1 + text2)

def get_radix_by_format(format):
    if format == Format.DIGITS:
        return 10

    if format == Format.CREDITCARD:
        return 10

    if format == Format.LETTERS:
        return len(mapping_letters[0])

    if format == Format.STRING:
        return len(mapping_all[0])

    if format == Format.EMAIL:        
        radix1 = len(mapping_letters_integer[0])
        radix2 = len(mapping_email_tail[0])
        radix3 = len(mapping_top_lvl_domains[0])
        return [radix1, radix2, radix3]

    if format == Format.CPR:
        radix1 = len(mapping_dates[0])
        radix2 = 10
        return [radix1, radix2]