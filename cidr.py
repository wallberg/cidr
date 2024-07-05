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
            if not isinstance(ip, int) or ip < 0 or ip >= 2**32:
                raise ValueError(f'Invalid ip: {ip}')

            self.bitmask = bitmask
            if not isinstance(ip, int) or bitmask < 0 or bitmask > 32:
                raise ValueError(f'Invalid bitmask: {bitmask}')

        else:
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
            raise ValueError("Second operand is not of type CidrSet")

        if self.size() == 0:
            return b.clone()

        a = self.clone()
        if b.size() == 0:
            return a

        # Traverse b in postorder (TAOCP, §2.3.1, Algorithm T, Exercise 13)
        # Simultaneously traverse a in the same order as b, making changes
        # to a as necessary

        # T1 [Initialize]
        b_stack = []  # b tree, node stack
        b_p = b.root # b tree, current node
        b_q = None # b tree, last node visited

        a_stack = []  # a tree, node stack
        a_p = a.root # a tree, current node
        a_created = None # a tree, most recently created a node

        goto = 'T2'
        while True:

            if goto == 'T2':  # [P = Λ?]
                goto = 'T4' if b_p is None else 'T3'
                # print(f"T2: {goto=}")

            if goto == 'T3':  # [Stack ⇐ P.]
                # print("T3: push")
                b_stack.append(b_p)
                a_stack.append(a_p)

                b_is_leaf = b_p.left is None and b_p.right is None
                a_is_leaf = a_p != a_created and a_p.left is None and a_p.right is None

                # print(f"T2: {a_is_leaf=}, {b_is_leaf=}, {(a_p == a_created)=}")
                if b_is_leaf ^ a_is_leaf:
                    print("here A")
                    # If node a is a leaf, then whatever is below node b is
                    # already included, so we can skip them.
                    if b_is_leaf:
                        # Node b is a leaf, so turn node a into a leaf also
                        a_p.left = None
                        a_p.right = None

                    # Skip left traversal
                    b_p = None
                    a_p = None

                elif b_p.left is None:
                    print("here B")
                    # Skip left traversal
                    b_p = None
                    a_p = None

                else:
                    # print("here C")
                    if a_p.left is None:
                        # Add left node to node a, to match node b left node
                        a_p.left = Node(a_p.value+1)
                        a_created = a_p.left

                    # Traverse left
                    b_p = b_p.left
                    a_p = a_p.left

                # if b_p is not None:
                #     print("T5: moved left")

                goto = 'T2'

            if goto == 'T4':  # [P ⇐ Stack.]
                # print("T4: pop")

                if len(b_stack) == 0:
                    return a

                b_p = b_stack.pop()
                a_p = a_stack.pop()
                # print(f"T4: {b_p.value=}, {a_p.value=}")

                goto = 'T5'

            if goto == 'T5':  # [Right branch done?]
                a_is_leaf = a_p != a_created and a_p.left is None and a_p.right is None
                # print(f"T5: {a_is_leaf=}, {b_is_leaf=}, {(a_p == a_created)=}")

                if a_is_leaf or b_p.right is None or b_p.right == b_q:
                    # print('T5: skip right')
                    # Skip right traversal: it's not necessary or already done
                    goto = 'T6'
                else:
                    b_stack.append(b_p)
                    b_p = b_p.right

                    a_stack.append(a_p)
                    if a_p.right is None and b_p is not None:
                        # print("T5: adding a_p.right node")
                        a_p.right = Node(a_p.value+1)
                        a_created = a_p.right
                    a_p = a_p.right

                    # if b_p is not None:
                    #     print("T5: moved right")

                    goto = 'T2'

            if goto == 'T6':  # [Visit P.]
                # print("T6: visit")
                # Check if a collapse is necessary because both child nodes are leaf nodes
                if (a_p.left is not None and a_p.right is not None
                    and a_p.left.left is None and a_p.left.right is None
                    and a_p.right.left is None and a_p.right.right is None):
                    # print("T6: collapsing a node")
                    a_p.left = None
                    a_p.right =  None

                b_q = b_p
                goto = 'T4'

    def __sub__(self, b):
        """ Support the subtraction operator, for two CidrSet objects. """

        if type(b) is not CidrSet:
            raise ValueError("Second operand is not of type CidrSet")

        a = self.clone()
        if self.size() == 0 or b.size() == 0:
            return a

        # Traverse b in postorder (TAOCP, §2.3.1, Algorithm T, Exercise 13)
        # Simultaneously traverse a in the same order as b, making changes
        # to a as necessary

        # T1 [Initialize]
        b_stack = []  # b tree, node stack
        b_p = b.root # b tree, current node
        b_q = None # b tree, last node visited

        a_stack = []  # a tree, node stack
        a_p = a.root # a tree, current node
        a_created = None # a tree, most recently created a node

        goto = 'T2'
        while True:

            if goto == 'T2':  # [P = Λ?]
                goto = 'T4' if b_p is None else 'T3'
                # print(f"T2: {goto=}")

            if goto == 'T3':  # [Stack ⇐ P.]
                # print("T3: push")
                b_stack.append(b_p)
                a_stack.append(a_p)

                if b_p.left is not None or b_p.right is not None:
                    if a_p.left is None:
                        a_p.left = Node(a_p.value+1)
                    if a_p.right is None:
                        a_p.right = Node(a_p.value+1)

                # Traverse left
                b_p = b_p.left
                a_p = a_p.left

                # if b_p is not None:
                #     print("T5: moved left")

                goto = 'T2'

            if goto == 'T4':  # [P ⇐ Stack.]
                # print("T4: pop")

                if len(b_stack) == 0:
                    # Traversal complete; check for node removal
                    if a.root is not None and b.root is not None:  # TODO: always True?

                        if b.root.left is None and b.root.right is None:
                            # Remove everything
                            a.root = None
                        elif b.root.left is None and b.root.right is not None:
                            if b.root.right.left is not None and b.root.right.right is not None:
                                a.root.right = None
                        elif b.root.left is not None and b.root.right is None:
                            if b.root.left.left is not None and b.root.left.right is not None:
                                a.root.left = None

                    return a

                b_p = b_stack.pop()
                a_p = a_stack.pop()
                # print(f"T4: {b_p.value=}, {a_p.value=}")

                goto = 'T5'

            if goto == 'T5':  # [Right branch done?]
                a_is_leaf = a_p != a_created and a_p.left is None and a_p.right is None
                # print(f"T5: {a_is_leaf=}, {b_is_leaf=}, {(a_p == a_created)=}")

                # if a_is_leaf or b_p.right is None or b_p.right == b_q:
                if b_p.right is None or b_p.right == b_q:
                    # print('T5: skip right')
                    # Skip right traversal: it's not necessary or already done
                    goto = 'T6'
                else:
                    b_stack.append(b_p)
                    b_p = b_p.right

                    a_stack.append(a_p)
                    # if a_p.right is None and b_p is not None:
                    #     # print("T5: adding a_p.right node")
                    #     a_p.right = Node(a_p.value+1)
                    #     a_created = a_p.right
                    a_p = a_p.right

                    # if b_p is not None:
                    #     print("T5: moved right")

                    goto = 'T2'

            if goto == 'T6':  # [Visit P.]
                # print("T6: visit")

                # Traversal complete; check for node removal
                if a_p.left is not None and b_p.left is not None:
                    if b_p.left.left is None and b_p.left.right is None:
                        # Remove everything
                        a_p.left = None
                    elif b_p.left.left is None and b_p.left.right is not None:
                        if b_p.left.right.left is not None and b_p.left.right.right is not None:
                            a_p.left.right = None
                    elif b_p.left.left is not None and b_p.left.right is None:
                        if b_p.left.left.left is not None and b_p.left.left.right is not None:
                            a_p.left.left = None

                if a_p.right is not None and b_p.right is not None:
                    if b_p.right.left is None and b_p.right.right is None:
                        # Remove everything
                        a_p.right = None
                    elif b_p.right.left is None and b_p.right.right is not None:
                        if b_p.right.right.left is not None and b_p.right.right.right is not None:
                            a_p.right.right = None
                    elif b_p.right.left is not None and b_p.right.right is None:
                        if b_p.right.left.left is not None and b_p.right.left.right is not None:
                            a_p.right.left = None

                b_q = b_p
                goto = 'T4'

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

    def __eq__(self, b):
        if type(b) is not CidrSet:
            raise ValueError("Second operand is not of type CidrSet")

        if self.root is None and b.root is None:
            return True

        elif self.root is not None and b.root is not None:
            return self.root.equals(b.root)

        else:
            return False

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
