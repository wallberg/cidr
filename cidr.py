import re

from binarytree import Node

cidrPattern = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(\/(\d{1,2}))?$')


class Cidr:
    """ Represent a single CIDR address as an integer IP part and the number of bits in the bitmask. """

    def __init__(self, s=None, ip=None, bitmask=None):

        if s is None:
            if ip is None or bitmask is None:
                raise ValueError('Must provide parameter: s or (ip and bitmask)')

            self.ip = ip
            if type(ip) != int or ip < 0 or ip >= 2**32:
                raise ValueError(f'Invalid ip: {ip}')

            self.bitmask = bitmask
            if type(ip) != int or bitmask < 0 or bitmask > 32:
                raise ValueError(f'Invalid bitmask: {bitmask}')

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
        self.bitmask = 32
        if m[6]:
            self.bitmask = int(m[6])
            if self.bitmask < 0 or self.bitmask > 32:
                raise ValueError("Invalid cidr bitmask (0-32): {self.bitmask}")

        # Normalize the IP by zeroing out the bits not covered by the bitmask
        self.ip = (self.ip >> (32-self.bitmask)) << (32-self.bitmask)

    def bit(self, n):
        """ n-th bit in this cidr (1-32). """
        return self.ip >> (32-n) & 1

    def __str__(self):
        return '{}.{}.{}.{}/{}'.format(
            self.ip >> 24 & 255,
            self.ip >> 16 & 255,
            self.ip >> 8 & 255,
            self.ip & 255,
            self.bitmask)

    def __rep__(self):
        return str(self)

    def __eq__(self, b):
        return self.ip == b.ip and self.bitmask == b.bitmask


class CidrSet:
    """ Represent a set of CIDR ranges as a binary tree. """

    def __init__(self, *args):
        # Start empty
        self.root = None

        self.extend(args)

    def extend(self, args):
        """ Add several items at once. """
        for arg in args:
            self.add(arg)

    def contains(self, cidr):
        """ Test if this cidr is in the set, ie every IP in the cidr is in the set. """

        if type(cidr) is not Cidr:
            return False

        if self.root is None:
            return False

        return self._contains(self.root, cidr)

    def _contains(self, node, cidr):
        """ Recursively test if this Cidr node is in the set. """

        # Base case, we've reached a leaf node
        if node.left is None and node.right is None:
            return True

        # Base case, we've reached the bottom of the cidr, but not a leaf node
        if cidr.bitmask == node.value:
            return False

        # Get depth and bit for the child node
        depth = node.value+1
        bit = cidr.bit(depth)

        if bit == 0:
            if node.left is None:
                return False
            return self._contains(node.left, cidr)
        else:
            if node.right is None:
                return False
            return self._contains(node.right, cidr)

    __contains__ = contains

    def add(self, cidr):
        """ Add a new cidr to the set. """

        # Store the depth in node.value and the bit values
        # are implied on the edges by node.left (0 bit) and node.right (1 bit)

        if self.root is None:
            self.root = Node(0)
            self._add(self.root, True, cidr)
        else:
            self._add(self.root, False, cidr)

    def _add(self, node, newnode, cidr):
        """ Recursively add a new CIDR node to the set. """

        # Base case, we've added a node for every bit, no more children
        # Existing children can be deleted
        if cidr.bitmask == node.value:
            node.left = None
            node.right = None
            return

        # Base case, we are at an existing leaf which already includes the cidr
        if not newnode and node.left is None and node.right is None:
            return

        # Get depth and bit for the child node
        depth = node.value+1
        bit = cidr.bit(depth)

        # Add a new child node
        newnode = False
        if bit == 0:
            if node.left is None:
                node.left = Node(depth)
                newnode = True
            child = node.left
        else:
            if node.right is None:
                node.right = Node(depth)
                newnode = True
            child = node.right

        # Recurse down to next level
        self._add(child, newnode, cidr)

        # Check if a collapse is necessary because both child nodes are leaf nodes
        if (node.left is not None and node.right is not None
           and node.left.left is None and node.left.right is None
           and node.right.left is None and node.right.right is None):

            node.left = None
            node.right = None

    def clone(self):
        """ Make a clone of this CidrSet. """
        c = CidrSet()
        if self.root is not None:
            c.root = self.root.clone()
        return c

    def __add__(self, b):
        """ Support the addition operator, for two CidrSet objects. """
        if type(b) is not CidrSet:
            raise ValueException("Second operand is not of type CidrSet")

        c = self.clone()
        for cidr in b:
            c.add(cidr)
        return c

    def __sub__(self, b):
        """ Support the subtraction operator, for two CidrSet objects. """
        if type(b) is not CidrSet:
            raise ValueException("Second operand is not of type CidrSet")

        c = self.clone()
        for cidr in b:
            c.remove(cidr)
        return c

    def remove(self, cidr: Cidr):
        """ Remove a Cidr node from the set. """

        if self.root is None:
            # Set is already empty
            return

        if self._remove(self.root, cidr):
            self.root = None

    def _remove(self, node, cidr):
        """ Recursively remove a Cidr node from the set.
        Returns True if this node should be removed.
        """

        # Base case, we've reached the bottom of the cidr; perfect match
        # so delete this node and any descendants
        if cidr.bitmask == node.value:
            return True

        # Get depth and bit for the child node
        depth = node.value+1
        bit = cidr.bit(depth)

        if bit == 0:
            if node.left is None:
                if node.right is None:
                    # Leaf node, trigger expansion
                    node.left = Node(depth)
                    node.right = Node(depth)
                else:
                    # cidr is not in this set
                    return False

            if self._remove(node.left, cidr):
                node.left = None
                if node.right is None:
                    # Now a leaf node, propogate the delete upward
                    return True

        else:
            if node.right is None:
                if node.left is None:
                    # Leaf node, trigger expansion
                    node.left = Node(depth)
                    node.right = Node(depth)
                else:
                    # cidr is not in this set
                    return False

            if self._remove(node.right, cidr):
                node.right = None
                if node.left is None:
                    # Now a leaf node, propogate the delete upward
                    return True

        return False

    def __len__(self):
        """ Support the len() function. """
        return self.size()

    def size(self) -> int:
        """ Return the number of cidrs in this set. """
        if self.root is None:
            return 0

        return self.root.leaf_count

    def __str__(self):
        return ", ".join([str(cidr) for cidr in self])

    def __rep__(self):
        return self.__str__()

    def __iter__(self, node=None, ip=None):
        """ Return an iterator over Cidr values in this set. """

        if node is None:
            if self.root is None:
                return
            yield from self.__iter__(node=self.root, ip=0)

        else:
            # Base case, leaf node so yield the Cidr
            if node.left is None and node.right is None:
                cidr = Cidr(ip=ip, bitmask=node.value)
                yield cidr
                return

            if node.left is not None:
                yield from self.__iter__(node=node.left, ip=ip)

            if node.right is not None:
                ip += 2**(32-node.right.value)
                yield from self.__iter__(node=node.right, ip=ip)
