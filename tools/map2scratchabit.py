#
# Parse mapfile and dump all information collected.
# Requires https://github.com/pfalcon/pymapfile .
#
import sys
import logging
from pprint import pprint

from mapfile import GnuMapFile


logging.basicConfig(level=logging.DEBUG)

f = open(sys.argv[1])
m = GnuMapFile(f)
m.skip_till_memmap()
m.skip_while_lead_space()
m.parse_sections()
m.validate()

basename = sys.argv[1].replace("-", "_").replace(".", "_")

with open(basename + ".subareas", "w") as f:
    print("[subareas]", file=f)
    for k, addr, sz in m.section_order:
        #print("%08x %08x %s" % (addr, sz, k))
        for sec, addr, sz, obj, symbols in m.sections[k]["objects"]:
            if sec.endswith(".literal"):
                obj += ".literal"
            obj = obj.replace(" ", "_")
            print("%s 0x%08x(0x%08x)" % (obj, addr, sz), file=f)
        print(file=f)

with open(basename + "_script.py", "w") as f:
    print("""\
from idc import *

""", file=f)
    for k, addr, sz in m.section_order:
        #print("%08x %08x %s" % (addr, sz, k))
        for sec, addr, sz, obj, symbols in m.sections[k]["objects"]:
            if obj.endswith(".fill"):
                print("# %s 0x%08x(0x%08x)" % (obj, addr, sz), file=f)
                print("MakeAlign(0x%08x, 0x%08x, 0)" % (addr, sz), file=f)
        print(file=f)
