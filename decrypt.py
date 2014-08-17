
import array
import os
import sys
import struct

class MersenneTwister(object):
    """ Standard Mersenne Twister """
    def __init__(self):
        self._state = [0 for i in xrange(624)]
        self._index = 0

    def seed(self, seed):
        self._state[0] = seed
        for i in xrange(1, 624):
            self._state[i] = (i + 0x6C078965 * (self._state[i - 1] ^ (self._state[i - 1] >> 30))) & 0xFFFFFFFF

    def _reseed(self):
        for i in xrange(624):
            y = (self._state[i] & 0x80000000) + (self._state[(i + 1) % 624] & 0x7FFFFFFF)
            self._state[i] = self._state[(i + 397) % 624] ^ (y >> 1)
            if y % 2 != 0:
                self._state[i] ^= 0x9908B0DF

    def next(self):
        if self._index == 0:
            self._reseed()
        y = self._state[self._index]
        y ^= (y >> 11)
        y ^= (y <<  7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y ^= (y >> 18)

        self._index = (self._index + 1) % 624
        return y

def get_rand_seed(basename):
    seed = 0x19570320
    for idx, char in enumerate(basename):
        m = ord(char) >> (idx & 3)
        seed = (seed * m) + ord(char) & 0xFFFFFFFF
    return seed

def get_file_key(basename):
    rng = MersenneTwister()
    seed = get_rand_seed(basename)
    rng.seed(seed)
    key = array.array('L', [rng.next() for i in xrange(4)])
    key.byteswap()
    return key

def get_basename(filename):
    basename = os.path.basename(filename).upper()
    basename, dot, ext = basename.rpartition('.')
    return basename

class Decrypter(object):
    def __init__(self, filename, key1, key2):
        self._filename = filename

        self._basename = get_basename(self._filename)
        self._file_key = get_file_key(self._basename)
        self._key1 = key1
        self._key2 = key2

        self._key1_buf = array.array('L', self._key1)
        self._key2_buf = array.array('L', self._key2)

    def _get_file_contents(self):
        with open(self._filename, 'rb') as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(0, os.SEEK_SET)

            buf = array.array('L')
            buf.fromfile(f, size / buf.itemsize)
            return buf

    def _descramble_keys(self):
        # Some shorthands.
        k1 = self._key1_buf
        k2 = self._key2_buf

        # Make sure that key1 has the filename data inside it.
        for i in xrange(len(k1)):
            k1[i] ^= self._file_key[i % len(self._file_key)]

        print hex(self._file_key[0])
        print hex(k1[0])
        asdf

        def descramble(a, b):
            v5 = a
            v4 = b

            for i in xrange(0, 16, 4):
                v1 = (v5 ^ k1[i+0])
                v2 = (v4 ^ k1[i+1] ^ k2[(v1 & 0xFF) + 0x300] + (k2[((v1 >> 8) & 0xFF) + 0x200] ^ (k2[((v1 >> 16) & 0xFF) + 0x100]) + k2[((v1 >> 24) & 0xFF)])) & 0xFFFFFFFF
                v3 = (v1 ^ k1[i+2] ^ k2[(v2 & 0xFF) + 0x300] + (k2[((v2 >> 8) & 0xFF) + 0x200] ^ (k2[((v2 >> 16) & 0xFF) + 0x100]) + k2[((v2 >> 24) & 0xFF)])) & 0xFFFFFFFF
                v4 = (v2 ^ k1[i+3] ^ k2[(v3 & 0xFF) + 0x300] + (k2[((v3 >> 8) & 0xFF) + 0x200] ^ (k2[((v3 >> 16) & 0xFF) + 0x100]) + k2[((v3 >> 24) & 0xFF)])) & 0xFFFFFFFF
                v5 = (v3           ^ k2[(v4 & 0xFF) + 0x300] + (k2[((v4 >> 8) & 0xFF) + 0x200] ^ (k2[((v4 >> 16) & 0xFF) + 0x100]) + k2[((v4 >> 24) & 0xFF)])) & 0xFFFFFFFF

            a = v4 ^ k1[17]
            b = v5 ^ k1[16]

            return a, b

        # Descramble the key buffers.
        a = 0
        b = 0
        for i in xrange(0, len(k1), 2):
            a, b = descramble(a, b)
            k1[i+0] = a
            k1[i+1] = b

        for i in xrange(0, len(k2), 2):
            a, b = descramble(a, b)
            k2[i+0] = a
            k2[i+1] = b

    def decrypt_file(self, out_filename):
        self._descramble_keys()

        buf = self._get_file_contents()

        def decrypt(a, b):
            k1 = self._key1_buf
            k2 = self._key2_buf

            v2 = a
            v3 = b

            for i in xrange(16):
                v1 = v2 ^ (k1[17 - i])
                v2 = v3 ^ (k2[(v1 & 0xFF) + 0x300] + (k2[((v1 >> 8) & 0xFF) + 0x200] ^ (k2[((v1 >> 16) & 0xFF) + 0x100]) + k2[((v1 >> 24) & 0xFF)])) & 0xFFFFFFFF
                v3 = v1

            a = v1 ^ k1[0]
            b = v2 ^ k1[1]
            return a, b

        with open(out_filename, 'wb') as f:
            for i in xrange(0, len(buf), 2):
                a = buf[i+0]
                b = buf[i+1]
                a, b = decrypt(a, b)
                if i > 4:
                    f.write(struct.pack('LL', a, b))

def load_key(fn):
    key = array.array('L')
    with open(fn, "rb") as f:
        f.seek(0, os.SEEK_END)
        sz = f.tell()
        f.seek(0, os.SEEK_SET)
        assert (sz % key.itemsize) == 0
        key.fromfile(f, sz / key.itemsize)
    return key

def main():
    key1 = load_key("key1")
    key2 = load_key("key2")

    filename = sys.argv[1]
    decrypter = Decrypter(filename, key1, key2)
    decrypter.decrypt_file('dec_' + filename)

if __name__ == "__main__":
    main()
