from code.utils import num_radix, str_radix

number = '12345'


def test_num_radix():
    number_radix = num_radix(10, number)
    print(number_radix)
    assert number_radix == int(number)


def test_str_radix():
    assert str_radix(10, 2, 10) == '10'
    assert str_radix(2, 3, 3) == '011'
