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

