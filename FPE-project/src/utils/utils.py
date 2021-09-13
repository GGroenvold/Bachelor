def num_radix(radix, number):
    x = 0
    for digit in number:
        x = x * radix + int(digit)
    return x


def str_radix(radix, length, number):
    if length < 1:
        raise ValueError(f"{length} is not a valid string length")

    if not (0 <= number <= radix ** length):
        raise ValueError(f"{number} is not in range [0;{radix}^{length}]")

    string = [''] * length
    for i in range(length):
        string[length - 1 - i] = str(number % radix)
        number = number // radix
    return ''.join(string)



