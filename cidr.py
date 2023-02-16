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

    def __contains__(self, cidr):
        """ Add support for the 'in' operator. """
        if type(cidr) is not Cidr:
            return False

        return self.contains(cidr)

    def contains(self, cidr):
        """ Test if this cidr is in the set, ie every IP in the cidr is in the set. """
        if self.root is None:
            return False

        return self._contains(self.root, cidr)

    def _contains(self, node, cidr):
        """ Recursively test if this cidr is in the set. """

        # Base case, we've reached a leaf node
        if node.left is None and node.right is None:
            return True

        # Base case, we've reached the bottom of the cidr, but not a leaf node
        if cidr.bits == node.value:
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
        if cidr.bits == node.value:
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
        for cidr in b.cidrs():
            c.add(cidr)
        return c

    def __sub__(self, b):
        """ Support the subtraction operator, for two CidrSet objects. """
        if type(b) is not CidrSet:
            raise ValueException("Second operand is not of type CidrSet")

        c = self.clone()
        for cidr in b.cidrs():
            c.sub(cidr)
        return c

    def sub(self, cidr: Cidr):
        """ Subtract a cidr to the set. """

        if self.root is None:
            # Set is already empty
            return

        if self._sub(self.root, cidr):
            self.root = None

    def _sub(self, node, cidr):
        """ Recursively subtract a CIDR node from the set.
        Returns True if this node should be removed.
        """

        # Base case, we've reached the bottom of the cidr; perfect match
        # so delete this node and any descendants
        if cidr.bits == node.value:
            return True

        # Get depth and bit for the child node
        depth = node.value+1
        bit = cidr.bit(depth)

        if bit == 0:
            if node.left is None:
                node.left = Node(depth)
                if node.right is None:
                    # Leaf node, trigger expansion
                    node.right = Node(depth)

            if self._sub(node.left, cidr):
                if node.right is None:
                    # Now a leaf node, propogate the delete upward
                    return True
                node.left = None

        else:
            if node.right is None:
                node.right = Node(depth)
                if node.left is None:
                    # Leaf node, trigger expansion
                    node.left = Node(depth)

            if self._sub(node.right, cidr):
                if node.left is None:
                    # Now a leaf node, propogate the delete upward
                    return True
                node.right = None

        return False

    def __len__(self):
        """ Support the len() function. """
        return self.size()

    def size(self) -> int:
        """ Return the number of cidrs in this set. """
        if self.root is None:
            return 0

        return self.root.leaf_count

    def cidrs(self) -> list:
        """ Output this set as a list of Cidr values. """

        result = []
        if self.root is not None:
            self._cidrs(self.root, 0, result)

        return result

    def _cidrs(self, node, ip, result):
        """ Traverse the tree, adding all Cidr values to the list. """

        # Base case, leaf node so add the Cidr
        if node.left is None and node.right is None:
            cidr = Cidr()
            cidr.ip = ip
            cidr.bits = node.value
            result.append(cidr)
            return

        if node.left is not None:
            self._cidrs(node.left, ip, result)

        if node.right is not None:
            self._cidrs(node.right, ip + 2**(32-node.right.value), result)

    def __str__(self):
        return ", ".join([str(cidr) for cidr in self.cidrs()])

    def __rep__(self):
        return self.__str__()
