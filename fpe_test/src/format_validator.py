from format import Format
import re


def validate_format(plaintext, format):
    if format == Format.LETTERS:
        p = re.compile('[a-zA-Z]+')
        return p.match(plaintext)

    if format == Format.DIGITS:
        p = re.compile('\d+')
        return p.match(plaintext)

    if format == Format.STRING:
        p = re.compile('.+')
        return p.match(plaintext)

