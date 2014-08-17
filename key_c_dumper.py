
import array
import os

def load_key(fn):
    key = array.array('L')
    with open(fn, "rb") as f:
        f.seek(0, os.SEEK_END)
        sz = f.tell()
        f.seek(0, os.SEEK_SET)
        assert (sz % key.itemsize) == 0
        key.fromfile(f, sz / key.itemsize)
    return key

def dump_key(f, key):
    for i in xrange(len(key)):
        if i % 6 == 0:
            f.write("\n  ")
        else:
            f.write(" ")
        n = key[i]
        f.write("0x%08lx," % (n,))

def write_key(f, name, data):
    varname = "%s_data" % (name,)
    f.write("static uint32_t %s[] = {" % (varname,))
    dump_key(f, data)
    f.write("\n};\n\n")

with open("keys.inc", "wb") as f:
    write_key(f, "key1", load_key("key1"))
    write_key(f, "key2", load_key("key2"))
