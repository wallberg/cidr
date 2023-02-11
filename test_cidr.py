import pytest

from .cidr import Cidr, CidrSet


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
    for n in range(1, 32):
        assert c.bit(n) == 0

    c = Cidr("255.255.255.254/32")
    for n in range(1, 33):
        if n == 32:
            assert c.bit(n) == 0
        else:
            assert c.bit(n) == 1


def test_cidr_eq():
    a = Cidr("255.255.255.255/1")
    b = Cidr("128.0.0.0/1")
    assert a == b

    a = Cidr("255.255.255.255/31")
    b = Cidr("255.255.255.254/32")
    assert a != b

    a = Cidr("255.255.255.254/32")
    b = Cidr("255.255.255.255/32")
    assert a != b


def test_cidrset():
    s = CidrSet()
    assert s.root is None

    s.add(Cidr("0.0.0.0/1"))
    assert s.root is not None


def test_cidrset_add():

    # Root-only Operations
    s = CidrSet()
    assert [str(cidr) for cidr in s.cidrs()] == []

    s.add(Cidr("0.0.0.0/0"))
    assert [str(cidr) for cidr in s.cidrs()] == [
        "0.0.0.0/0",
    ]

    # Add-only operations
    s = CidrSet()
    s.add(Cidr("0.0.0.0/1"))
    assert [str(cidr) for cidr in s.cidrs()] == [
        "0.0.0.0/1",
    ]

    s.add(Cidr("0.0.0.0/3"))
    assert [str(cidr) for cidr in s.cidrs()] == [
        "0.0.0.0/3",
    ]

    s.add(Cidr("0.0.0.0/2"))
    assert [str(cidr) for cidr in s.cidrs()] == [
        "0.0.0.0/3",
    ]

    s.add(Cidr("255.0.0.0/4"))
    assert [str(cidr) for cidr in s.cidrs()] == [
        "0.0.0.0/3",
        "240.0.0.0/4",
    ]

    s.add(Cidr("255.0.0.0/2"))
    assert [str(cidr) for cidr in s.cidrs()] == [
        "0.0.0.0/3",
        "240.0.0.0/4",
    ]

    s.add(Cidr("168.0.0.0/6"))
    assert [str(cidr) for cidr in s.cidrs()] == [
        "0.0.0.0/3",
        "168.0.0.0/6",
        "240.0.0.0/4",
    ]

    s.add(Cidr("255.255.255.255"))
    assert [str(cidr) for cidr in s.cidrs()] == [
        "0.0.0.0/3",
        "168.0.0.0/6",
        "255.255.255.255/32",
    ]

    # Add operations (with collapse)
    s.add(Cidr("255.255.255.254"))
    assert [str(cidr) for cidr in s.cidrs()] == [
        "0.0.0.0/3",
        "168.0.0.0/6",
        "255.255.255.254/31",
    ]

    s.add(Cidr("255.0.0.0/8"))
    assert [str(cidr) for cidr in s.cidrs()] == [
        "0.0.0.0/3",
        "168.0.0.0/6",
        "255.255.255.254/31",
    ]

    s.add(Cidr("255.0.0.0/9"))
    assert [str(cidr) for cidr in s.cidrs()] == [
        "0.0.0.0/3",
        "168.0.0.0/6",
        "255.0.0.0/9",
        "255.255.255.254/31",
    ]

    s = CidrSet()
    s.add(Cidr("128.0.0.0/1"))
    assert [str(cidr) for cidr in s.cidrs()] == [
        "128.0.0.0/1",
    ]

    s.add(Cidr("192.0.0.0/2"))
    assert [str(cidr) for cidr in s.cidrs()] == [
        "192.0.0.0/2",
    ]

    s.add(Cidr("128.0.0.0/2"))
    assert [str(cidr) for cidr in s.cidrs()] == [
        "128.0.0.0/1",
    ]

    s.add(Cidr("32.0.0.0/3"))
    assert [str(cidr) for cidr in s.cidrs()] == [
        "32.0.0.0/3",
        "128.0.0.0/1",
    ]

    s.add(Cidr("64.0.0.0/2"))
    assert [str(cidr) for cidr in s.cidrs()] == [
        "32.0.0.0/3",
        "64.0.0.0/2",
        "128.0.0.0/1",
    ]

    s.add(Cidr("16.0.0.0/4"))
    assert [str(cidr) for cidr in s.cidrs()] == [
        "16.0.0.0/4",
        "32.0.0.0/3",
        "64.0.0.0/2",
        "128.0.0.0/1",
    ]

    s.add(Cidr("0.0.0.0/4"))
    assert [str(cidr) for cidr in s.cidrs()] == [
        "0.0.0.0/0",
    ]
