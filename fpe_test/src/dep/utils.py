from numpy import arange


def num_radix(radix, numbers):
    x = 0
    for numeral in numbers:
        x = x * radix + int(numeral)
    return x


def str_radix(radix, length, number):
    if length < 1:
        raise ValueError(f"{length} is not a valid string length")

    if not (0 <= number <= radix ** length):
        raise ValueError(f"{number} is not in range [0;{radix}^{length}]")

    numerals = [''] * length

    for i in range(length):
        numerals[length - 1 - i] = str(number % radix)
        number = number // radix
    return numerals


def reverse(string):
    return string[::-1]


def map_from_numeral_string(numeral_string, mapping):
    return [mapping[numeral] for numeral in numeral_string]


def map_from_name(name, mapping):
    return (mapping[(name)])


def get_mapping_from_domain(domain):
    index = list(map(int, arange(0, len(domain)).tolist()))
    return [dict(zip(domain, index)), dict(zip(index, domain))]


def validateCard(cardNumber):
    sum = 0
    for index in range(len(cardNumber)):
        if (index % 2 == 0):
            sum += (int(cardNumber[index]) * 2) % 9
        else:
            sum += int(cardNumber[index])
    return str((10 - sum) % 10)

def validateCPR(CPR):
        weights = [4, 3, 2, 7, 6, 5, 4, 3, 2]
        sum = 0
        for digit in range(len(CPR)):
            sum += (int(CPR[digit]) * weights[digit])
        if(11 - (sum % 11))%11==10:
            return '0'
        else:
            return str((11 - (sum % 11))%11)
