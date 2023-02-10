import re

cidrPattern = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(\/(\d{1,2}))?$')


class Cidr:
    """ Represent a single CIDR address as an integer IP part and the number of bits in the bitmask. """

    def __init__(self, s=None):

        if s is None:
            self.ip = 0
            self.bits = 0
            return

        if (m := cidrPattern.match(s)) is None:
            raise ValueError(f'Invalid cidr format: {s}')

        # Extract the IP address
        self.ip = 0
        for i in (1, 2, 3, 4):
            octet = int(m[i])
            if octet < 0 or octet > 255:
                raise ValueError(f'Invalid cidr octet format: {octet}')
            self.ip *= 256
            self.ip += octet

        # Extract the optional length of the bitmask
        self.bits = 32
        if m[6]:
            self.bits = int(m[6])
            if self.bits < 0 or self.bits > 32:
                raise ValueError("Invalid cidr bits (0-32): {self.bits}")

        # Normalize the IP by zeroing out the bits not covered by the bitmask
        self.ip = (self.ip >> (32-self.bits)) << (32-self.bits)

    def bit(self, n):
        """ n-th bit in this cidr (1-32). """
        return self.ip >> (32-n) & 1

    def __str__(self):
        return '{}.{}.{}.{}/{}'.format(
            self.ip >> 24 & 255,
            self.ip >> 16 & 255,
            self.ip >> 8 & 255,
            self.ip & 255,
            self.bits)

    def __eq__(self, b):
        return self.ip == b.ip and self.bits == b.bits


class CidrNode:
    """ Represent a single node in a CidrSet tree. """

    def __init__(self, parent=None, depth=0, child0=None, child1=None):
        self.parent = parent  # parent CidrNode
        self.depth = depth  # depth of the node in bits (1-32)
        self.child0 = child0  # left branch - 0 bit
        self.child1 = child1  # right branch - 1 bit

    def isLeaf(self):
        """ True if this is a leaf node, no children. """
        return self.child0 is None and self.child1 is None

    def isRange(self):
        """ True if this is a leaf node and depth ∈ [1, 32). """
        return self.isLeaf() and self.depth > 0 and self.depth < 32

