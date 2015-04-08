# ScratchABit - interactive disassembler
#
# Copyright (c) 2015 Paul Sokolovsky
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#from cStringIO import StringIO
import sys
from io import StringIO

# IDA standard 6
MAX_OPERANDS = 6

dt_byte = "dt_byte"
dt_word = "dt_word"
dt_dword = "dt_dword"
DATA_SIZE = {dt_byte: 1, dt_word: 2, dt_dword: 4}

o_void = "-"
o_imm = "o_imm"
o_reg = "o_reg"
o_mem = "o_mem"
o_near = "o_near"
class BADADDR: pass

class cvar:
    pass

class op_t:

    def __init__(self):
        self.type = None

    def __repr__(self):
        return str(self.__dict__)

class insn_t:

    def __init__(self, ea=0):
        self.ea = ea
        self.size = 0
        self.itype = 0
        self._operands = [op_t() for i in range(MAX_OPERANDS)]
        self.disasm = None

    def get_canon_feature(self):
        return _processor.instruc[self.itype]["feature"]

    def __getitem__(self, i):
        return self._operands[i]

    def __repr__(self):
        return str(self.__dict__)

    def __len__(self):
        return len(self.disasm)

    def get_operand_addr(self):
        # Assumes RISC design with one address operand!
        for o in self._operands:
            if o.type in (o_near, o_mem):
                return o


cmd = insn_t()

class processor_t:
    def __init__(self):
        self.cmd = cmd

PR_SEGS = 1
PR_DEFSEG32 = 2
PR_RNAMESOK = 4
PR_ADJSEGS = 8
PRN_HEX = 16
PR_USE32 = 32

ASH_HEXF3 = 1
ASD_DECF0 = 2
ASO_OCTF1 = 4
ASB_BINF3 = 8
AS_NOTAB = 16
AS_ASCIIC = 32
AS_ASCIIZ = 64

OOFW_IMM = 1

# Basic instruction semantics
CF_CALL = 1
CF_STOP = 2

fl_CN = 1  # "call near"
fl_JN = 2  # "jump near"
fl_F = 3   # "ordinary flow"

# Data references
dr_R = 1
dr_W = 2


COLOR_ERROR = "*"

_processor = None
u_line = None

def set_processor(p):
    global _processor
    _processor = p

def init_output_buffer(n):
    global u_line
    u_line = StringIO()
    return u_line

def term_output_buffer():
    pass

def OutMnem(width):
    global _processor, u_line
#    print(_processor.instruc[cmd.itype])
    s = _processor.instruc[_processor.cmd.itype]["name"]
    if len(s) < width:
        s += " " * (width - len(s))
    u_line.write(s)

def OutChar(c):
    global u_line
    u_line.write(c)

#        // This call to out_symbol() is another helper function in the
#        // IDA kernel.  It writes the specified character to the current
#        // buffer, using the user-configurable 'symbol' color.
def out_symbol(c):
    OutChar(c)

# Append string
def OutLine(s):
    global u_line
    u_line.write(s)

def out_one_operand(op_no):
    global _processor, u_line
    _processor.outop(_processor.cmd[op_no])

def OutValue(op, flags):
    global u_line
#    print(op, flags)
    u_line.write(str(op.value))

def out_name_expr(op, ea, offset):
    global u_line
#    print(op, ea, offset)
    assert offset == BADADDR
    label = ADDRESS_SPACE.get_label(ea)
    if label:
        u_line.write(label)
    else:
        u_line.write(hex(ea))
    return True

def out_tagon(tag):
    pass

def out_register(reg):
    OutLine(reg)

def MakeLine(sb):
#    global cmd
    global _processor
    _processor.cmd.disasm = sb.getvalue()


START = 0
END = 1
PROPS = 2
BYTES = 3
FLAGS = 4

class AddressSpace:
    UNK = 0
    CODE = 0x80
    CODE_CONT = 0x40
    DATA = 0x20
    DATA_CONT = 0x10

    def __init__(self):
        self.area_list = []
        # Map from area start address to area byte content
        self.area_bytes = {}
        # Map from area start address to each byte's flags
        self.area_byte_flags = {}
        # Map from referenced addresses to their properties
        self.addr_map = {}
        self.labels = {}

    def add_area(self, start, end, flags):
        sz = end - start + 1
        bytes = bytearray(sz)
        flags = bytearray(sz)
        a = (start, end, flags, bytes, flags)
        self.area_list.append(a)

    def addr2area(self, addr):
        for a in self.area_list:
            if a[0] <= addr <= a[1]:
                return (addr - a[0], a)

    def load_content(self, addr, file):
        off, area = self.addr2area(addr)
        file.readinto(memoryview(area[BYTES])[off:])

    def get_byte(self, addr):
        off, area = self.addr2area(addr)
        return area[BYTES][off]

    def get_data(self, addr, sz):
        off, area = self.addr2area(addr)
        val = 0
        for i in range(sz):
            val = val | (area[BYTES][off + i] << 8 * i)
        return val

    def get_flags(self, addr):
        off, area = self.addr2area(addr)
        return area[FLAGS][off]

    def note_code(self, addr, sz):
        off, area = self.addr2area(addr)
        area_byte_flags = area[FLAGS]
        area_byte_flags[off] |= self.CODE
        for i in range(sz - 1):
            area_byte_flags[off + 1 + i] |= self.CODE_CONT

    def note_data(self, addr, sz):
        off, area = self.addr2area(addr)
        area_byte_flags = area[FLAGS]
        area_byte_flags[off] |= self.DATA
        for i in range(sz - 1):
            area_byte_flags[off + 1 + i] |= self.DATA_CONT

    def make_label(self, ea):
        self.labels[ea] = "loc_%08x" % ea

    def get_label(self, ea):
        return self.labels.get(ea)


ADDRESS_SPACE = AddressSpace()

def get_full_byte(ea):
    return ADDRESS_SPACE.get_byte(ea)


analisys_stack = []

def add_entrypoint(ea):
    analisys_stack.append(ea)

def init_cmd(ea):
    _processor.cmd.ea = ea
    _processor.cmd.size = 0
    _processor.cmd.disasm = None

def analyze(callback=lambda cnt:None):
    cnt = 0
    limit = 40000
    while analisys_stack and limit:
        ea = analisys_stack.pop()
        init_cmd(ea)
        insn_sz = _processor.ana()
#        print("size: %d" % insn_sz, _processor.cmd)
        if insn_sz:
            if not _processor.emu():
                assert False
            ADDRESS_SPACE.note_code(ea, insn_sz)
            _processor.out()
#            print("%08x %s" % (_processor.cmd.ea, _processor.cmd.disasm))
#            print("---------")
            limit -= 1
            cnt += 1
            if cnt % 1000 == 0:
                callback(cnt)
#    if not analisys_stack:
#        print("Analisys finished")

def ua_add_cref(opoff, ea, flags):
    fl = ADDRESS_SPACE.get_flags(ea)
    if fl == AddressSpace.UNK:
        analisys_stack.append(ea)
    else:
        assert fl == AddressSpace.CODE
    if flags != fl_F:
        ADDRESS_SPACE.make_label(ea)


def ua_dodata2(opoff, ea, dtype):
#    print(opoff, hex(ea), dtype)
#    address_map[ea] = {"type": type, "access": set()}
    ADDRESS_SPACE.note_data(ea, DATA_SIZE[dtype])

def ua_add_dref(opoff, ea, access):
    #address_map[ea]["access"].add(access)
    pass


class Model:

    def __init__(self):
        self._lines = []
        self._cnt = 0
        self._addr2line = {}

    def lines(self):
        return self._lines

    def add_line(self, addr, line):
        self._lines.append(line)
        self._addr2line[addr] = self._cnt
        self._cnt += 1

    def addr2line_no(self, addr):
        return self._addr2line.get(addr)


def render():
    model = Model()
    for a in ADDRESS_SPACE.area_list:
        bytes = a[BYTES]
        flags = a[FLAGS]
        i = 0
        while i < len(flags):
            addr = a[START] + i

            label = ADDRESS_SPACE.get_label(addr)
            if label:
                model.add_line(addr, "%08x %s:" % (addr, label))

            out = "%08x " % addr
            f = flags[i]
            if f == AddressSpace.UNK:
                out += "unk 0x%02x" % bytes[i]
                i += 1
            elif f == AddressSpace.DATA:
                sz = 1
                j = i + 1
                while flags[j] == AddressSpace.DATA_CONT:
                    sz += 1
                    j += 1
                out += "%s 0x%x" % ({1:"db",2:"dw",4:"dd"}[sz], ADDRESS_SPACE.get_data(addr, sz))
                i += sz
            elif f == AddressSpace.CODE:
                insn = insn_t(addr)
                _processor.cmd = insn
                insn_sz = _processor.ana()
                _processor.out()
                out = insn
                i += insn_sz
            else:
                assert 0

            model.add_line(addr, out)
#            sys.stdout.write(out + "\n")
    return model


def flag2char(f):
    if f == AddressSpace.UNK:
        return "."
    elif f == AddressSpace.CODE:
        return "C"
    elif f == AddressSpace.CODE_CONT:
        return "c"
    elif f == AddressSpace.DATA:
        return "D"
    elif f == AddressSpace.DATA_CONT:
        return "d"
    else:
        return "X"

import sys
def print_address_map():
    for a in ADDRESS_SPACE.area_list:
        for i in range(len(a[FLAGS])):
            if i % 128 == 0:
                sys.stdout.write("\n")
                sys.stdout.write("%08x " % (a[START] + i))
            sys.stdout.write(flag2char(a[FLAGS][i]))
        sys.stdout.write("\n")

