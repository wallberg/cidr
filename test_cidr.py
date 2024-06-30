import pytest
from random import seed, randint, triangular

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

    c = Cidr(ip=511, bitmask=1)
    assert str(c) == "0.0.0.0/1"

    c = Cidr(ip=511, bitmask=32)
    assert str(c) == "0.0.1.255/32"

    with pytest.raises(ValueError, match=r"Invalid cidr format"):
        c = Cidr("255")

    with pytest.raises(ValueError, match=r"Invalid cidr octet format"):
        c = Cidr("255.255.255.256")

    with pytest.raises(ValueError, match=r"Invalid cidr bitmask"):
        c = Cidr("0.0.0.0/33")

    with pytest.raises(ValueError, match=r"Must provide parameter"):
        c = Cidr()

    with pytest.raises(ValueError, match=r"Invalid ip"):
        c = Cidr(ip=-1, bitmask=0)

    with pytest.raises(ValueError, match=r"Invalid bitmask"):
        c = Cidr(ip=0, bitmask=33)


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

    s = CidrSet(Cidr("0.0.0.0/32"), Cidr("255.255.255.255/32"))
    assert s.size() == 2


def test_cidrset_extend():
    s = CidrSet()
    s.extend([Cidr("0.0.0.0/32"), Cidr("255.255.255.255/32")])
    assert s.size() == 2


def test_cidrset_contains():
    s = CidrSet()
    assert Cidr("0.0.0.0/0") not in s
    assert 2 not in s

    s.add(Cidr("0.0.0.0/0"))
    assert Cidr("0.0.0.0/0") in s
    assert Cidr("0.0.0.0/1") in s
    assert Cidr("255.0.0.0/1") in s

    s = CidrSet()
    s.add(Cidr("0.0.0.0/32"))
    s.add(Cidr("255.255.255.255/32"))
    assert Cidr("0.0.0.0/32") in s
    assert Cidr("255.255.255.255/32") in s
    assert Cidr("0.0.0.0/31") not in s
    assert Cidr("255.255.255.255/31") not in s
    assert Cidr("0.0.0.1/32") not in s
    assert Cidr("255.255.255.254/32") not in s

    s = CidrSet()
    s.add(Cidr("0.0.0.0/31"))
    s.add(Cidr("255.255.255.255/31"))
    assert Cidr("0.0.0.0/32") in s
    assert Cidr("0.0.0.0/31") in s
    assert Cidr("0.0.0.2/31") not in s
    assert Cidr("255.255.255.255/32") in s
    assert Cidr("255.255.255.255/31") in s
    assert Cidr("255.255.255.253/31") not in s
    assert Cidr("64.0.0.0/2") not in s
    assert Cidr("128.0.0.0/2") not in s


def test_cidrset_clone():
    a = CidrSet()
    b = a.clone()
    assert type(b) is CidrSet
    assert b.root is None

    a.add(Cidr("0.0.0.0/31"))
    b = a.clone()
    assert [str(cidr) for cidr in a] == [
        "0.0.0.0/31",
    ]
    assert [str(cidr) for cidr in b] == [
        "0.0.0.0/31",
    ]

    a.remove(Cidr("0.0.0.1/32"))
    b.add(Cidr("0.0.0.0/30"))
    assert [str(cidr) for cidr in a] == [
        "0.0.0.0/32",
    ]
    assert [str(cidr) for cidr in b] == [
        "0.0.0.0/30",
    ]


def test_cidrset_add():

    # Root-only Operations
    s = CidrSet()
    assert [str(cidr) for cidr in s] == []

    s.add(Cidr("0.0.0.0/0"))
    assert [str(cidr) for cidr in s] == [
        "0.0.0.0/0",
    ]

    # Add-only operations
    s = CidrSet()

    s.add(Cidr("0.0.0.0/3"))
    assert [str(cidr) for cidr in s] == [
        "0.0.0.0/3",
    ]

    s.add(Cidr("0.0.0.0/1"))
    assert [str(cidr) for cidr in s] == [
        "0.0.0.0/1",
    ]

    s.add(Cidr("0.0.0.0/2"))
    assert [str(cidr) for cidr in s] == [
        "0.0.0.0/1",
    ]

    s.add(Cidr("255.0.0.0/4"))
    assert [str(cidr) for cidr in s] == [
        "0.0.0.0/1",
        "240.0.0.0/4",
    ]

    s.add(Cidr("255.0.0.0/2"))
    assert [str(cidr) for cidr in s] == [
        "0.0.0.0/1",
        "192.0.0.0/2",
    ]

    s.add(Cidr("168.0.0.0/6"))
    assert [str(cidr) for cidr in s] == [
        "0.0.0.0/1",
        "168.0.0.0/6",
        "192.0.0.0/2",
    ]

    s.add(Cidr("255.255.255.255"))
    assert [str(cidr) for cidr in s] == [
        "0.0.0.0/1",
        "168.0.0.0/6",
        "192.0.0.0/2",
    ]

    # Add operations (with collapse)
    s = CidrSet()
    s.add(Cidr("255.255.255.255"))
    s.add(Cidr("255.255.255.254"))
    assert [str(cidr) for cidr in s] == [
        "255.255.255.254/31",
    ]

    s = CidrSet()
    s.add(Cidr("0.0.0.0/8"))
    s.add(Cidr("1.0.0.0/8"))
    assert [str(cidr) for cidr in s] == [
        "0.0.0.0/7",
    ]

    s = CidrSet()
    s.add(Cidr("128.0.0.0/1"))
    assert [str(cidr) for cidr in s] == [
        "128.0.0.0/1",
    ]

    s.add(Cidr("32.0.0.0/3"))
    assert [str(cidr) for cidr in s] == [
        "32.0.0.0/3",
        "128.0.0.0/1",
    ]

    s.add(Cidr("64.0.0.0/2"))
    assert [str(cidr) for cidr in s] == [
        "32.0.0.0/3",
        "64.0.0.0/2",
        "128.0.0.0/1",
    ]

    s.add(Cidr("16.0.0.0/4"))
    assert [str(cidr) for cidr in s] == [
        "16.0.0.0/4",
        "32.0.0.0/3",
        "64.0.0.0/2",
        "128.0.0.0/1",
    ]

    s.add(Cidr("0.0.0.0/4"))
    assert [str(cidr) for cidr in s] == [
        "0.0.0.0/0",
    ]


def test_cidrset_remove():
    s = CidrSet()

    s.add(Cidr("0.0.0.0/0"))
    s.remove(Cidr("0.0.0.0/0"))
    assert [str(cidr) for cidr in s] == [
    ]

    s.add(Cidr("0.0.0.0/0"))
    s.remove(Cidr("255.0.0.0/1"))
    assert [str(cidr) for cidr in s] == [
        "0.0.0.0/1",
    ]

    s.remove(Cidr("0.0.0.0/32"))
    assert [str(cidr) for cidr in s] == [
        "0.0.0.1/32",
        "0.0.0.2/31",
        "0.0.0.4/30",
        "0.0.0.8/29",
        "0.0.0.16/28",
        "0.0.0.32/27",
        "0.0.0.64/26",
        "0.0.0.128/25",
        "0.0.1.0/24",
        "0.0.2.0/23",
        "0.0.4.0/22",
        "0.0.8.0/21",
        "0.0.16.0/20",
        "0.0.32.0/19",
        "0.0.64.0/18",
        "0.0.128.0/17",
        "0.1.0.0/16",
        "0.2.0.0/15",
        "0.4.0.0/14",
        "0.8.0.0/13",
        "0.16.0.0/12",
        "0.32.0.0/11",
        "0.64.0.0/10",
        "0.128.0.0/9",
        "1.0.0.0/8",
        "2.0.0.0/7",
        "4.0.0.0/6",
        "8.0.0.0/5",
        "16.0.0.0/4",
        "32.0.0.0/3",
        "64.0.0.0/2",
    ]

    s.remove(Cidr("0.0.0.0/4"))
    assert [str(cidr) for cidr in s] == [
        "16.0.0.0/4",
        "32.0.0.0/3",
        "64.0.0.0/2",
    ]

    s.remove(Cidr("0.0.0.0/0"))
    assert [str(cidr) for cidr in s] == [
    ]

    s.add(Cidr("0.0.0.0/3"))
    s.add(Cidr("64.0.0.0/3"))
    assert [str(cidr) for cidr in s] == [
        "0.0.0.0/3",
        "64.0.0.0/3",
    ]

    s.remove(Cidr("0.0.0.0/3"))
    assert [str(cidr) for cidr in s] == [
        "64.0.0.0/3",
    ]

    s.remove(Cidr("64.0.0.0/2"))
    assert [str(cidr) for cidr in s] == [
    ]

    s.add(Cidr("0.0.0.0/32"))
    s.add(Cidr("255.255.255.255/32"))
    assert [str(cidr) for cidr in s] == [
        "0.0.0.0/32",
        "255.255.255.255/32",
    ]

    s.remove(Cidr("255.255.255.255/32"))
    assert [str(cidr) for cidr in s] == [
        "0.0.0.0/32",
    ]

    s.remove(Cidr("0.0.0.0/32"))
    assert [str(cidr) for cidr in s] == [
    ]

    s = CidrSet()
    s.add(Cidr("0.0.0.0/32"))
    s.remove(Cidr("0.0.0.2/32"))
    assert [str(cidr) for cidr in s] == [
        "0.0.0.0/32",
    ]


def test_cidrset_addoperator():

    a = CidrSet()

    with pytest.raises(ValueError):
        a == 1

    b = CidrSet()
    s = a + b
    assert type(s) is CidrSet
    assert len(s) == 0

    a = CidrSet(Cidr("0.0.0.0"))
    b = CidrSet()
    s = a + b
    assert [str(cidr) for cidr in s] == [
        "0.0.0.0/32",
    ]

    a = CidrSet(Cidr("0.0.0.0"))
    b = CidrSet(Cidr("0.0.0.0"))
    s = a + b
    assert [str(cidr) for cidr in s] == [
        "0.0.0.0/32",
    ]

    a = CidrSet(Cidr("0.0.0.0/1"))
    b = CidrSet(Cidr("128.0.0.0/1"))
    s = a + b
    assert [str(cidr) for cidr in s] == [
        "0.0.0.0/0",
    ]

    a = CidrSet(Cidr("128.0.0.0/1"))
    b = CidrSet(Cidr("0.0.0.0/0"))
    s = a + b
    assert [str(cidr) for cidr in s] == [
        "0.0.0.0/0",
    ]

    a = CidrSet(Cidr("0.0.0.0/0"))
    b = CidrSet(Cidr("128.0.0.0/1"))
    s = a + b
    assert [str(cidr) for cidr in s] == [
        "0.0.0.0/0",
    ]

    a = CidrSet(Cidr("0.0.0.0/2"))
    b = CidrSet(Cidr("192.0.0.0/2"))
    s = a + b
    assert [str(cidr) for cidr in s] == [
        "0.0.0.0/2",
        "192.0.0.0/2"
    ]

    a = CidrSet(Cidr("192.0.0.0/2"))
    b = CidrSet(Cidr("0.0.0.0/2"))
    s = a + b
    assert [str(cidr) for cidr in s] == [
        "0.0.0.0/2",
        "192.0.0.0/2"
    ]

    a = CidrSet(Cidr("0.0.0.0"))
    b = CidrSet(Cidr("0.0.0.0"), Cidr("255.255.255.255"))
    s = a + b
    assert [str(cidr) for cidr in s] == [
        "0.0.0.0/32",
        "255.255.255.255/32",
    ]

    a.add(Cidr("255.255.255.254"))
    s = a + b
    assert [str(cidr) for cidr in s] == [
        "0.0.0.0/32",
        "255.255.255.254/31",
    ]

    a = CidrSet(Cidr("0.0.0.0/31"))
    b = CidrSet(Cidr("0.0.0.0/32"))
    s = a + b
    assert [str(cidr) for cidr in s] == [
        "0.0.0.0/31",
    ]

    a = CidrSet(Cidr("0.0.0.0/32"))
    b = CidrSet(Cidr("0.0.0.0/31"))
    s = a + b
    assert [str(cidr) for cidr in s] == [
        "0.0.0.0/31",
    ]


def test_cidrset_suboperator():
    a = CidrSet()
    b = CidrSet()
    s = a - b
    assert type(s) is CidrSet
    assert len(s) == 0

    a = CidrSet(Cidr("0.0.0.0/0"))
    b = CidrSet()
    s = a - b
    assert [str(cidr) for cidr in s] == [
        "0.0.0.0/0",
    ]

    a = CidrSet()
    b = CidrSet(Cidr("0.0.0.0/0"))
    s = a - b
    assert [str(cidr) for cidr in s] == [
    ]

    # b.add(Cidr("0.0.0.0"))
    # s = a - b
    # assert len(s) == 0

    # b -= b
    # assert len(b) == 0

    # a.add(Cidr("0.0.0.0/0"))
    # b.add(Cidr("0.0.0.0/2"))
    # b.add(Cidr("255.255.255.255/2"))
    # s = a - b
    # assert [str(cidr) for cidr in s] == [
    #     "64.0.0.0/2",
    #     "128.0.0.0/2"
    # ]

    # s = a - b - a
    # assert len(s) == 0


def test_cidrset_eq():
    a = CidrSet()

    with pytest.raises(ValueError):
        a == 1

    b = CidrSet()
    assert a == b

    a.add(Cidr("0.0.0.0/0"))
    assert a != b

    b.add(Cidr("0.0.0.0/0"))
    assert a == b

    b.remove(Cidr("128.0.0.0/1"))
    assert a != b


def test_cidrset_iter():
    s = CidrSet()
    assert len(list(s)) == 0

    s.add(Cidr("0.0.0.0/2"))
    assert [str(cidr) for cidr in s] == [
        "0.0.0.0/2",
    ]

    s.add(Cidr("255.255.255.255/1"))
    assert [str(cidr) for cidr in s] == [
        "0.0.0.0/2",
        "128.0.0.0/1",
    ]


def test_cidrset_ops():
    """ Compare results of add/remove ops vs __add__/__sub__ ops. """

    a = CidrSet()
    b = CidrSet()
    i = 0

    def test_add():
        # x = a + b
        y = a.clone()
        for cidr in b:
            y.add(cidr)
        # if x != y:
        #     print(f"{i=}")
        #     print(a.size())
        #     for cidr in a:
        #         print(f"a: {str(cidr)=}")
        #     print(b.size())
        #     for cidr in b:
        #         print(f"b: {str(cidr)=}")
        #     print(x.size())
        #     for cidr in x:
        #         print(f"x: {str(cidr)=}")
        #     print(y.size())
        #     for cidr in y:
        #         print(f"y: {str(cidr)=}")
        #     assert False

    def test_sub():
        x = a - b
        y = a.clone()
        for cidr in b:
            y.remove(cidr)
        assert x == y

    def test_both():
        test_add()
        test_sub()

    a.add(Cidr("0.0.0.0/32"))
    test_both()

    a.add(Cidr("0.0.0.1/32"))
    test_both()

    b.add(Cidr("0.0.0.0/32"))
    test_both()

    # Randomly add and remove Cidr values
    seed(0)
    for i in range(100):
        cidr = Cidr(
            ip = randint(0,255) * 256**3 + randint(0,255) * 256**2 + randint(0,255) * 256**1 + randint(0,255) * 256**0,
            bitmask = int(triangular(8,33,33))
        )

        if randint(0,1) == 0:
            a.add(cidr)
        else:
            b.add(cidr)

        test_both()

    # Add everything in a to b
    c = b.clone()
    for cidr in a:
        b.add(cidr)
        test_both()

    # Test node expand and collapse
    b = c.clone()
    for cidr in a:
        # Flip the final bit
        cidr_new = Cidr(
            ip = cidr.ip ^ 2**(32-cidr.bitmask),
            bitmask = cidr.bitmask,
        )
        b.add(cidr_new)
        test_both()

