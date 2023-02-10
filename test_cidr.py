import pytest

from .cidr import Cidr


def test_cidr():
    c = Cidr("0.0.0.0/0")
    assert str(c) == "0.0.0.0/0"

    c = Cidr("255.255.255.255/0")
    assert str(c) == "0.0.0.0/0"

    c = Cidr("1.2.0.255/32")
    assert str(c) == "1.2.0.255/32"

    c = Cidr("255.255.255.255/1")
    assert str(c) == "128.0.0.0/1"

    c = Cidr("255.255.255.255")
    assert str(c) == "255.255.255.255/32"

    c = Cidr("255.0.0.0")
    assert str(c) == "255.0.0.0/32"

    with pytest.raises(ValueError, match=r"Invalid cidr format"):
        c = Cidr("255")

    with pytest.raises(ValueError, match=r"Invalid cidr octet format"):
        c = Cidr("255.255.255.256")

    with pytest.raises(ValueError, match=r"Invalid cidr bits"):
        c = Cidr("0.0.0.0/33")


def test_cidr_bit():
    c = Cidr("0.0.0.0/0")
    for n in range(0, 32):
        assert c.bit(n) == 0

    c = Cidr("255.255.255.254/32")
    for n in range(1, 33):
        if n == 32:
            assert c.bit(n) == 0
        else:
            assert c.bit(n) == 1
