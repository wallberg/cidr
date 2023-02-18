# cidr

Experimental library for storing and manipulating sets of [CIDR](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing) format IP ranges.

## Usage

See [test_cidr.py](test_cidr.py) for more comprehensive usage via testing.

### Cidr Class

The Cidr class represents a single CIDR range.

```python
from cidr import Cidr

# Create a Cidr using the CIDR format
a = Cidr("0.0.0.0")
assert str(a) == "0.0.0.0/32"

b = Cidr("255.255.255.255/31")
assert str(b) == "255.255.255.254/31"

# Creat a Cidr using the specific ip and bitmask
c = Cidr(ip=511, bitmask=32)
assert str(c) == "0.0.1.255/32"
assert c.bit(1) == 0
assert c.bit(32) == 1
```

### CidrSet Class

The CidrSet class represents a set of CIDR ranges and supports set-like operations.

```python
from cidr import Cidr, CidrSet

# Create a new CidrSet
a = CidrSet(Cidr("0.0.0.0/1"))
assert len(a) == 1
assert Cidr("0.0.0.1/32") in a
assert Cidr("128.0.0.1/32") not in a

# Add to the set (collapses to higher range)
a.add(Cidr("128.0.0.0/1"))
assert len(a) == 1
assert str(list(a)[0]) == "0.0.0.0/0"

# Remove from the set (expaneds to lower ranges)
b = CidrSet(Cidr("0.0.0.0/2"), Cidr("255.255.255.255/2"))
c = a - b
assert [str(cidr) for cidr in c] == [
        "64.0.0.0/2",
        "128.0.0.0/2"
]
```

## License

See the [LICENSE.txt](LICENSE.txt) file for license rights and limitations.
