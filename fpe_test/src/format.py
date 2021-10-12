from enum import Enum, auto
from utils import *
import json

RADIX_DEFAULT = 10

data = json.loads(open("names.json", "r").read())
names = []
for name in data['names']:
    names.append(name['name'])

DOMAIN = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
          'w', 'x', 'y', 'z',
          'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
          'W', 'X', 'Y', 'Z',
          '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
          '.', '-', '!', '#', '$', '£', '%', '&', '\'', '*', '+', '/', '=', '?', '^', '_', '´', '{', '}', '|']

# Indices
LOWER_LETTER_INDEX = 0
UPPER_LETTER_INDEX = 26
INTEGER_INDEX = 52
SPECIAL_SIGNS_INDEX = 62

mapping_letters = get_mapping_from_domain(DOMAIN[:INTEGER_INDEX])
mapping_upper_letters = get_mapping_from_domain(DOMAIN[UPPER_LETTER_INDEX:INTEGER_INDEX])
mapping_lower_letters = get_mapping_from_domain(DOMAIN[:UPPER_LETTER_INDEX])
mapping_email_tail = get_mapping_from_domain(
    DOMAIN[:UPPER_LETTER_INDEX] + DOMAIN[INTEGER_INDEX:SPECIAL_SIGNS_INDEX + 2])
mapping_letters_integer = get_mapping_from_domain(DOMAIN[:SPECIAL_SIGNS_INDEX])
mapping_all = get_mapping_from_domain(DOMAIN)
mapping_name = get_mapping_from_domain(names)


class Format(Enum):
    DEFAULT = auto()
    DIGITS = auto()
    CREDITCARD = auto()
    LETTERS = auto()
    STRING = auto()
    EMAIL = auto()
    DATE = auto()
    NAME = auto()


def plaintext_to_numeral_string(plaintext, format):
    if format == Format.DEFAULT:
        return plaintext

    if format == Format.DIGITS:
        return ''.join(plaintext)

    if format == Format.LETTERS:
        mapping = mapping_letters
        return map_from_numeral_string(plaintext, mapping[0])

    if format == Format.STRING:
        mapping = mapping_letters_integer
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
        mapping = mapping_letters_integer
        return map_from_numeral_string(numeral_string, mapping[1])


def get_radix_by_format(format):
    if format == Format.DEFAULT:
        return RADIX_DEFAULT

    if format == Format.DIGITS:
        return 10

    if format == Format.LETTERS:
        return len(mapping_letters)

    if format == Format.STRING:
        return len(mapping_letters_integer[0])
