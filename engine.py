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
import sys
import logging as log

import idaapi

#
# ScratchABit API and code
#

START = 0
END = 1
PROPS = 2
BYTES = 3
FLAGS = 4

def str_area(area):
    return "Area(0x%x-0x%x)" % (area[START], area[END])

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
        # Map from address to its label
        self.labels = {}
        # Map from code/data unit to properties of its args
        # at the very least, this should differentiate between literal
        # numeric values and addresses/offsets/pointers to other objects
        self.arg_props = {}
        # Cached last accessed area
        self.last_area = None

    def add_area(self, start, end, flags):
        sz = end - start + 1
        bytes = bytearray(sz)
        flags = bytearray(sz)
        a = (start, end, flags, bytes, flags)
        self.area_list.append(a)

    def area_no(self, area):
        return self.area_list.index(area)

    def addr2area(self, addr):
        if self.last_area:
            a = self.last_area
            if a[0] <= addr <= a[1]:
                return (addr - a[0], a)
        for a in self.area_list:
            if a[0] <= addr <= a[1]:
                self.last_area = a
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

    def get_unit_size(self, addr):
        off, area = self.addr2area(addr)
        flags = area[FLAGS]
        sz = 1
        if flags[off] == self.CODE:
            f = self.CODE_CONT
        elif flags[off] == self.DATA:
            f = self.DATA_CONT
        else:
            return 1
        off += 1
        while flags[off] == f:
            off += 1
            sz += 1
        return sz

    # Taking an offset inside unit, return offset to the beginning of unit
    @classmethod
    def adjust_offset_reverse(cls, off, area):
        flags = area[FLAGS]
        while off > 0:
            if flags[off] in (cls.CODE_CONT, cls.DATA_CONT):
                off -= 1
            else:
                break
        return off


    def set_flags(self, addr, sz, head_fl, rest_fl=0):
        off, area = self.addr2area(addr)
        flags = area[FLAGS]
        flags[off] = head_fl
        off += 1
        for i in range(sz - 1):
            flags[off + i] = rest_fl

    def undefine(self, addr, sz):
        self.set_flags(addr, sz, self.UNK, self.UNK)

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

    def make_label(self, prefix, ea):
        if not prefix:
            f = self.get_flags(ea)
            if f == self.CODE:
                prefix = "loc_"
            elif f & self.DATA:
                prefix = "dat_"
            else:
                prefix = "unk_"
        self.labels[ea] = "%s%08x" % (prefix, ea)

    def get_label(self, ea):
        return self.labels.get(ea)

    def set_label(self, ea, label):
        self.labels[ea] = label

    def set_arg_prop(self, ea, arg_no, prop, prop_val):
        if ea not in self.arg_props:
            self.arg_props[ea] = {}
        arg_props = self.arg_props[ea]
        if arg_no not in arg_props:
            arg_props[arg_no] = {}
        props = arg_props[arg_no]
        props[prop] = prop_val

    def get_arg_prop(self, ea, arg_no, prop):
        return self.arg_props.get(ea, {}).get(arg_no, {}).get(prop)

    # Hack for idaapi interfacing
    # TODO: should go to "Analysis" object
    @staticmethod
    def analisys_stack_push(ea):
        global analisys_stack
        analisys_stack.append(ea)

ADDRESS_SPACE = AddressSpace()
_processor = None
def set_processor(p):
    global _processor
    _processor = p
    idaapi.set_processor(p)


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



class Model:

    def __init__(self, target_addr=0):
        self._lines = []
        self._cnt = 0
        self._addr2line = {}
        self.AS = None
        self.target_addr = target_addr
        self.target_addr_lineno = -1

    def lines(self):
        return self._lines

    def add_line(self, addr, line):
        if addr == self.target_addr:
            self.target_addr_lineno = self._cnt
        self._lines.append(line)
        self._addr2line[addr] = self._cnt
        self._cnt += 1

    # Insert virtual line, i.e. line whose byte size == 0
    # In other words, lien which doesn't cause shift in addresses
    # of lines following it.
    def insert_vline(self, pos, addr, line):
        self._lines[pos:pos] = [line]
        self._cnt += 1
        end = self._cnt
        pos += 1
        while pos < end:
            line = self._lines[pos]
            if isinstance(line, Instruction):
                self._addr2line[line.ea] += 1
            pos += 1

    def addr2line_no(self, addr):
        return self._addr2line.get(addr)

    def undefine(self, addr):
        sz = self.AS.get_unit_size(addr)
        self.AS.undefine(addr, sz)


def data_sz2mnem(sz):
    s = {1: "db", 2: "dw", 4: "dd"}[sz]
    return idaapi.fillstr(s, idaapi.DEFAULT_WIDTH)

# Size of address field in disasm window
ADDR_FIELD_SIZE = 9

class DisasmObj:

    # ea =

    def render(self):
        # Render object as a string, set as .cache, and return
        pass

    def get_operand_addr(self):
        return None

    def __len__(self):
        try:
            return ADDR_FIELD_SIZE + len(self.cache)
        except AttributeError:
            return ADDR_FIELD_SIZE + len(self.render())


class Instruction(idaapi.insn_t, DisasmObj):

    def render(self):
        _processor.cmd = self
        _processor.out()
        s = self.disasm
        self.cache = s
        return s

    def get_operand_addr(self):
        # Assumes RISC design with one address operand!
        for o in self._operands:
            if o.type in (idaapi.o_near, idaapi.o_mem):
                return o

class Label(DisasmObj):

    def __init__(self, ea):
        self.ea = ea

    def render(self):
        label = ADDRESS_SPACE.get_label(self.ea)
        s = "%s:" % label
        self.cache = s
        return s

class Data(DisasmObj):

    def __init__(self, ea, sz, val):
        self.ea = ea
        self.sz = sz
        self.val = val

    def render(self):
        # o_mem is the closest thing, possibly have o_offset?
        if ADDRESS_SPACE.get_arg_prop(self.ea, 0, "type") == idaapi.o_mem:
            s = "%s%s" % (data_sz2mnem(self.sz), ADDRESS_SPACE.get_label(self.val))
        else:
            s = "%s0x%x" % (data_sz2mnem(self.sz), self.val)
        self.cache = s
        return s

    def get_operand_addr(self):
        o = idaapi.op_t(0)
        o.addr = self.val
        return o

class Literal(DisasmObj):

    def __init__(self, ea, str):
        self.ea = ea
        self.cache = str

    def render(self):
        return self.cache


def render():
    model = Model()
    render_partial(model, 0, 0, 1000000)
    return model

# How much bytes may a single disasm object (i.e. a line) occupy
MAX_UNIT_SIZE = 4

def render_partial_around(addr, context_lines):
    log.debug("render_partial_around(%x)", addr)
    off, area = ADDRESS_SPACE.addr2area(addr)
    back = context_lines * MAX_UNIT_SIZE
    off -= back
    if off < 0:
        area_no = ADDRESS_SPACE.area_no(area) - 1
        while area_no >= 0:
            area = ADDRESS_SPACE.area_list[area_no]
            sz = area[1] - area[0] + 1
            off += sz
            if off >= 0:
                break
            area_no -= 1
        if off < 0:
            # Reached beginning of address space, just set as such
            off = 0
    assert off >= 0
    log.debug("render_partial_around: %x, %s", off, str_area(area))
    off = ADDRESS_SPACE.adjust_offset_reverse(off, area)
    log.debug("render_partial_around adjusted: %x, %s", off, str_area(area))
    model = Model(addr)
    render_partial(model, ADDRESS_SPACE.area_list.index(area), off, context_lines, addr)
    log.debug("render_partial_around model done, lines: %d", len(model.lines()))
    assert model.target_addr_lineno >= 0
    return model


def render_partial(model, area_no, offset, num_lines, target_addr=-1):
    model.AS = ADDRESS_SPACE
    start = True
    #for a in ADDRESS_SPACE.area_list:
    while area_no < len(ADDRESS_SPACE.area_list):
        a = ADDRESS_SPACE.area_list[area_no]
        area_no += 1
        i = 0
        if start:
            i = offset
            start = False
        bytes = a[BYTES]
        flags = a[FLAGS]
        while i < len(flags):
            addr = a[START] + i
            # If we didn't yet reach target address, compensate for
            # the following decrement of num_lines. The logic is:
            # render all lines up to target_addr, and then num_lines past it.
            if target_addr >= 0 and addr < target_addr:
                num_lines += 1

            label = ADDRESS_SPACE.get_label(addr)
            if label:
                model.add_line(addr, Label(addr))

            f = flags[i]
            if f == AddressSpace.UNK:
                out = Literal(addr, "%s0x%02x" % (idaapi.fillstr("unk", idaapi.DEFAULT_WIDTH), bytes[i]))
                i += 1
            elif f == AddressSpace.DATA:
                sz = 1
                j = i + 1
                while flags[j] == AddressSpace.DATA_CONT:
                    sz += 1
                    j += 1
                out = Data(addr, sz, ADDRESS_SPACE.get_data(addr, sz))
                i += sz
            elif f == AddressSpace.CODE:
                out = Instruction(addr)
                _processor.cmd = out
                insn_sz = _processor.ana()
                _processor.out()
                i += insn_sz
            else:
                assert 0, "flags=%x" % f

            model.add_line(addr, out)
            #sys.stdout.write(out + "\n")
            num_lines -= 1
            if not num_lines:
                return


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

def print_address_map():
    for a in ADDRESS_SPACE.area_list:
        for i in range(len(a[FLAGS])):
            if i % 128 == 0:
                sys.stdout.write("\n")
                sys.stdout.write("%08x " % (a[START] + i))
            sys.stdout.write(flag2char(a[FLAGS][i]))
        sys.stdout.write("\n")


idaapi.set_address_space(ADDRESS_SPACE)
