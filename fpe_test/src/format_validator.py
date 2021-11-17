from format import Format
import re


def validate_format(plaintext, dataFormat):
    if dataFormat == Format.LETTERS:
        p = re.compile('[a-zA-Z]+')
        return p.match(plaintext)

    if dataFormat == Format.DIGITS:
        p = re.compile('\d+')
        return p.match(plaintext)

    if dataFormat == Format.STRING:
        p = re.compile('.+')
        return p.match(plaintext)

