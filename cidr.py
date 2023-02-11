import re

from binarytree import Node

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

    def __rep__(self):
        return str(self)

    def __eq__(self, b):
        return self.ip == b.ip and self.bits == b.bits


class CidrSet:
    """ Represent a set of CIDR ranges as a binary tree. """

    def __init__(self):
        # Start empty
        self.root = None

    def add(self, cidr):
        """ Add a new cidr to the set. """

        # Store the depth in node.value and the bit values
        # are implied by node.left (0 bit) and node.right (1 bit)
        if self.root is None:
            self.root = Node(0)

        self._add(self.root, cidr)

    def _add(self, node, cidr):
        """ Recursively add a new CIDR node to the set. """

        if cidr.bits == node.value:
            return

        # Get depth and bit for the child node
        depth = node.value+1
        bit = cidr.bit(depth)

        # Add a new child node (0 bit=left, 1 bit=right)
        if bit == 0:
            if node.left is None:
                node.left = Node(depth)
            child = node.left

        else:
            if node.right is None:
                node.right = Node(depth)
            child = node.right

        self._add(child, cidr)

    def cidrs(self) -> list:
        """ Output this set as a list of Cidr values. """

        result = []
        if self.root is not None:
            self._cidrs(self.root, 0, result)

        return result

    def _cidrs(self, node: Node, ip: int, result: list):
        """ Traverse the tree, adding all Cidr values to the list. """

        # print(node.value, ip, node.left is not None, node.right is not None)

        if node.left is None and node.right is None:
            # Leaf node, add the Cidr
            cidr = Cidr()
            cidr.ip = ip
            cidr.bits = node.value
            # print(f'Add {cidr}')
            result.append(cidr)
            return

        if node.left is not None:
            self._cidrs(node.left, ip, result)

        if node.right is not None:
            self._cidrs(node.right, ip + 2**(32-node.right.value), result)
