from utils import *
from format import Format
from format_validator import validate_format
import json

RADIX_DEFAULT = 10

data = json.loads(open("src/dates.json", "r").read())
dates = []
for i in data['dates']:
    dates.append(i['date'])
    
data = json.loads(open("src/top-lvl-domains.json", "r").read())
top_lvl_domains = []
for top_lvl_domain in data['top-lvl-domains']:
    top_lvl_domains.append(top_lvl_domain['top-lvl-domain'])
    


data = json.loads(open('src/names.json', "r").read())
names = []
for name in data['names']:
    names.append(name['name'])

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
mapping_email_tail = get_mapping_from_domain(DOMAIN[:LOWER_LETTER_END]+DOMAIN[UPPER_LETTER_END:INTEGER_END+2])
mapping_letters_integer = get_mapping_from_domain(DOMAIN[:INTEGER_END])
mapping_all = get_mapping_from_domain(DOMAIN)
mapping_dates = get_mapping_from_domain(dates)
mapping_name = get_mapping_from_domain(names)
mapping_top_lvl_domains = get_mapping_from_domain(top_lvl_domains)


def plaintext_to_numeral_string(plaintext, format):
    if not validate_format(plaintext, format):
        raise ValueError(f"The provided text is not correctly formatted as {format}")

    if format == Format.DEFAULT:
        return plaintext

    if format == Format.DIGITS:
        return ''.join(plaintext)

    if format == Format.LETTERS:
        mapping = mapping_letters
        return map_from_numeral_string(plaintext, mapping[0])

    if format == Format.STRING:
        mapping = mapping_all
        return map_from_numeral_string(plaintext, mapping[0])


def numeral_string_to_plaintext(numeral_string, format):
    if format == Format.DEFAULT:
        pass

    if format == Format.DIGITS:
        return ''.join(numeral_string)

    if format == Format.LETTERS:
        mapping = mapping_letters
        return map_from_numeral_string(numeral_string, mapping[1])

    if format == Format.STRING:
        mapping = mapping_all
        return map_from_numeral_string(numeral_string, mapping[1])

    if format == Format.NAME:
        pass

    if format == Format.EMAIL:
        pass



def get_radix_by_format(format):
    if format == Format.DEFAULT:
        return RADIX_DEFAULT

    if format == Format.DIGITS:
        return 10

    if format == Format.LETTERS:
        return len(mapping_letters[0])

    if format == Format.STRING:
        return len(mapping_all[0])
