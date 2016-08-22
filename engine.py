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
import binascii
import json
import logging as log

from rangeset import RangeSet

import idaapi
import idc

#
# ScratchABit API and code
#

START = 0
END = 1
PROPS = 2
BYTES = 3
FLAGS = 4

IMM_UHEX = None
IMM_SHEX = "shex"
IMM_UDEC = "udec"
IMM_SDEC = "sdec"
IMM_CHAR = "chr"
IMM_ADDR = "addr"

def str_area(area):
    if not area:
        return "Area(None)"
    return "Area(0x%x-0x%x, %s)" % (area[START], area[END], area[PROPS])

def area_props(area):
    return area[PROPS]


class InvalidAddrException(Exception):
    "Thrown when dereferencing address which doesn't exist in AddressSpace."
    def __init__(self, addr):
        self.args = (addr, hex(addr))


class Function:

    def __init__(self, start, end=None):
        self.ranges = RangeSet()
        self.start = start
        self.end = end

    def add_insn(self, addr, sz):
        self.ranges.add((addr, addr + sz))

    def add_range(self, start, end):
        self.ranges.add((start, end))

    def get_ranges(self):
        return self.ranges.to_list()

    def get_end(self):
        if self.end is not None:
            return self.end
        bounds = self.ranges.bounds()
        if bounds:
            return bounds[1]

    def get_end_method(self):
        if self.end is not None:
            return "as set by loader (detected: 0x%x)" % (self.ranges.bounds()[1] - 1)
        return "as detected"

class AddressSpace:
    UNK = 0
    CODE = 0x01
    CODE_CONT = 0x02
    DATA = 0x04
    DATA_CONT = 0x08
    STR = 0x10  # Continuation is DATA_CONT
    FILL = 0x40  # Filler/alignment bytes
    FUNC = 0x80  # Can appear with CODE, meaning this instruction belongs to a function

    def __init__(self):
        self.area_list = []
        # Map from referenced addresses to their properties. Among them:
        # "args":
        # Properties of instruction's args; at the very least, this should
        # differentiate between literal numeric values and addresses/offsets/pointers
        # to other objects
        # "comm":
        # Comment
        # "label"
        # Label
        # "xref":
        # Cross-reference records
        # "fun_s", "fun_e"
        # Function start and beyond-end addresses, map to Function object
        self.addr_map = {}
        # Map from label to its address
        self.labels_rev = {}
        # Problem spots which automatic control/data flow couldn't resolve
        self.issues = {}
        # Cached last accessed area
        self.last_area = None

    # Memory Area API

    def add_area(self, start, end, props):
        log.debug("add_area(%x, %x, %s)", start, end, props)
        sz = end - start + 1
        bytes = bytearray(sz)
        flags = bytearray(sz)
        a = (start, end, props, bytes, flags)
        self.area_list.append(a)
        # Area list should be sorted. Assume it's short and just resort it each time.
        self.area_list.sort()
        return a

    def get_areas(self):
        return self.area_list

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
        return (None, None)

    def min_addr(self):
        return self.area_list[0][START]

    def max_addr(self):
        return self.area_list[-1][END]

    # Return next address in the address space, or None
    def next_addr(self, addr):
        offset, area = self.addr2area(addr)
        if addr != area[END]:
            return addr + 1
        i = self.area_no(area) + 1
        if i == len(self.area_list):
            return None
        return self.area_list[i][START]

    def is_exec(self, addr):
        off, area = self.addr2area(addr)
        if not area:
            return False
        return "X" in area[PROPS]["access"]

    # Binary Data API

    def load_content(self, file, addr, sz=None):
        off, area = self.addr2area(addr)
        to = off + sz if sz else None
        file.readinto(memoryview(area[BYTES])[off:to])

    def is_valid_addr(self, addr):
        off, area = self.addr2area(addr)
        return area is not None

    def get_byte(self, addr):
        off, area = self.addr2area(addr)
        if area is None:
            raise InvalidAddrException(addr)
        return area[BYTES][off]

    def set_byte(self, addr, val):
        off, area = self.addr2area(addr)
        if area is None:
            raise InvalidAddrException(addr)
        area[BYTES][off] = val & 0xff

    def get_bytes(self, addr, sz):
        off, area = self.addr2area(addr)
        if area is None:
            raise InvalidAddrException(addr)
        return area[BYTES][off:off + sz]

    def get_data(self, addr, sz):
        # TODO: address size
        if sz == 4:
            sym = self.get_addr_prop(addr, "sym")
            if sym is not None:
                return sym

        off, area = self.addr2area(addr)
        val = 0
        for i in range(sz):
            val = val | (area[BYTES][off + i] << 8 * i)
        return val

    def set_data(self, addr, data, sz):
        off, area = self.addr2area(addr)
        val = 0
        for i in range(sz):
            area[BYTES][off + i] = data & 0xff
            data >>= 8

    # Binary Data Flags API

    def get_flags(self, addr, mask=0x7f):
        off, area = self.addr2area(addr)
        if area is None:
            raise InvalidAddrException(addr)
        return area[FLAGS][off] & mask

    def get_unit_size(self, addr):
        off, area = self.addr2area(addr)
        flags = area[FLAGS]
        sz = 1
        if flags[off] & 0x7f == self.CODE:
            f = self.CODE_CONT
        elif flags[off] in (self.DATA, self.STR):
            f = self.DATA_CONT
        elif flags[off] == self.FILL:
            f = self.FILL
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
        org_flags = flags[off]
        while off > 0:
            if flags[off] in (cls.CODE_CONT, cls.DATA_CONT, cls.FILL):
                off -= 1
            else:
                break
        if org_flags == cls.FILL and off > 0:
            off += 1
        return off

    def adjust_addr_reverse(self, addr):
        off, area = self.addr2area(addr)
        if area is None:
            return None
        return self.adjust_offset_reverse(off, area) + area[START]

    def set_flags(self, addr, sz, head_fl, rest_fl=0):
        off, area = self.addr2area(addr)
        flags = area[FLAGS]
        flags[off] = head_fl
        off += 1
        for i in range(sz - 1):
            flags[off + i] = rest_fl

    def make_undefined(self, addr, sz):
        self.set_flags(addr, sz, self.UNK, self.UNK)

    def make_code(self, addr, sz, extra_flags=0):
        off, area = self.addr2area(addr)
        area_byte_flags = area[FLAGS]
        area_byte_flags[off] |= self.CODE | extra_flags
        for i in range(sz - 1):
            area_byte_flags[off + 1 + i] |= self.CODE_CONT

    def make_data(self, addr, sz):
        off, area = self.addr2area(addr)
        area_byte_flags = area[FLAGS]
        area_byte_flags[off] |= self.DATA
        for i in range(sz - 1):
            area_byte_flags[off + 1 + i] |= self.DATA_CONT

    def make_data_array(self, addr, sz, num_items):
        # Make a data array. First-class arrays are not supported so far,
        # so just mark data units sequentially
        self.set_comment(addr, "Array, num %s: %d" % ("bytes" if sz == 1 else "items", num_items))
        for i in range(num_items):
            self.make_data(addr, sz)
            addr += sz

    def make_filler(self, addr, sz):
        self.set_flags(addr, sz, self.FILL, self.FILL)

    # Address properties API

    def set_addr_prop(self, addr, prop, val):
        self.addr_map.setdefault(addr, {})[prop] = val

    def get_addr_prop(self, addr, prop, default=None):
        return self.addr_map.get(addr, {}).get(prop, default)

    def get_addr_prop_dict(self, addr):
        return self.addr_map.get(addr, {})

    # Label API

    def get_default_label_prefix(self, ea):
        fl = self.get_flags(ea)
        if fl == self.CODE:
            prefix = "loc_"
        elif fl & self.DATA:
            prefix = "dat_"
        else:
            prefix = "unk_"
        return prefix

    def get_default_label(self, ea):
        prefix = self.get_default_label_prefix(ea)
        return "%s%08x" % (prefix, ea)

    def make_label(self, prefix, ea):
        l = self.get_addr_prop(ea, "label")
        if isinstance(l, str):
            # If it's real label, don't change it
            return
        if not prefix:
            prefix = self.get_default_label_prefix(ea)
        l = "%s%08x" % (prefix, ea)
        self.set_addr_prop(ea, "label", l)
        self.labels_rev[l] = ea

    # auto_label will change its prefix automatically based on
    # type of data it points.
    def make_auto_label(self, ea):
        if self.get_addr_prop(ea, "label"):
            return
        self.set_addr_prop(ea, "label", ea)
        self.labels_rev[ea] = ea

    # Delete a label, only if it's auto
    def del_auto_label(self, ea):
        label = self.get_addr_prop(ea, "label")
        if not label or isinstance(label, str):
            return
        self.set_addr_prop(ea, "label", None)
        del self.labels_rev[ea]

    def get_label(self, ea):
        label = self.get_addr_prop(ea, "label")
        if isinstance(label, int):
            return "%s%08x" % (self.get_default_label_prefix(ea), label)
        return label

    def set_label(self, ea, label):
        # Make sure the label can be actually visible - create an area for it if none
        off, area = self.addr2area(ea)
        if area is None:
            self.add_area(ea, ea, {"name": "autocreated to host %s label" % label})
        self.set_addr_prop(ea, "label", label)
        self.labels_rev[label] = ea

    def make_unique_label(self, ea, label):
        existing = self.get_label(ea)
        if existing == label:
            return label
        cnt = 0
        while True:
            l = label
            if cnt > 0:
                l += "__%d" % cnt
            if l not in self.labels_rev:
                self.set_label(ea, l)
                return l
            cnt += 1

    def get_label_list(self):
        return sorted([x if isinstance(x, str) else self.get_default_label(x) for x in self.labels_rev.keys()])

    def resolve_label(self, label):
        if label in self.labels_rev:
            return self.labels_rev[label]
        try:
            ea = int(label.split("_", 1)[1], 16)
        except:
            return None
        if ea in self.labels_rev and self.get_default_label(ea) == label:
            return ea

    def label_exists(self, label):
        return label in self.labels_rev

    # Comment API

    def get_comment(self, ea):
        comm = self.get_addr_prop(ea, "comm")
        return comm

    def set_comment(self, ea, comm):
        self.set_addr_prop(ea, "comm", comm)

    # (Pseudo)instruction Argument Properties API

    def set_arg_prop(self, ea, arg_no, prop, prop_val):
        arg_props = self.get_addr_prop(ea, "args", {})
        if arg_no not in arg_props:
            arg_props[arg_no] = {}
        props = arg_props[arg_no]
        props[prop] = prop_val
        self.set_addr_prop(ea, "args", arg_props)

    def get_arg_prop(self, ea, arg_no, prop):
        arg_props = self.get_addr_prop(ea, "args", {})
        return arg_props.get(arg_no, {}).get(prop)

    def get_arg_prop_dict(self, ea, arg_no):
        arg_props = self.get_addr_prop(ea, "args", {})
        return arg_props.get(arg_no, {})

    def make_arg_offset(self, insn_addr, arg_no, ref_addr):
        # Convert an immediate argument to an offset one
        # insn_addr - address of (pseudo)instruction
        # arg_no - argument no. of instruction
        # ref_addr - value of the argument (i.e. address it refers to)
        old_subtype = self.get_arg_prop(insn_addr, arg_no, "subtype")
        if old_subtype and old_subtype != IMM_ADDR:
            # Preserve old numeric value subtype to unconvert back to it
            # if need.
            self.set_arg_prop(insn_addr, arg_no, "num_subtype", old_subtype)

        self.set_arg_prop(insn_addr, arg_no, "subtype", IMM_ADDR)

        if isinstance(ref_addr, str):
            # Symbolic address
            # TODO: this works only for "dd" virtual instruction
            self.set_addr_prop(insn_addr, "sym", ref_addr)
            return

        label = self.get_label(ref_addr)
        if not label:
            self.make_auto_label(ref_addr)
        self.add_xref(insn_addr, ref_addr, idaapi.dr_O)

    def unmake_arg_offset(self, insn_addr, arg_no, ref_addr):
        # Convert offset argument to normal immediate value
        old_subtype = self.get_arg_prop(insn_addr, arg_no, "num_subtype")
        self.set_arg_prop(insn_addr, arg_no, "subtype", old_subtype)
        self.del_xref(insn_addr, ref_addr, idaapi.dr_O)
        # If this was last xref, and label is automatic, kill it too
        if not self.get_xrefs(ref_addr):
            self.del_auto_label(ref_addr)


    # Xref API

    def add_xref(self, from_ea, to_ea, type):
        xrefs = self.get_addr_prop(to_ea, "xrefs", {})
        xrefs[from_ea] = type
        self.set_addr_prop(to_ea, "xrefs", xrefs)

    def del_xref(self, from_ea, to_ea, type):
        xrefs = self.get_addr_prop(to_ea, "xrefs", {})
        del xrefs[from_ea]
        self.set_addr_prop(to_ea, "xrefs", xrefs)

    def get_xrefs(self, ea):
        xrefs = self.get_addr_prop(ea, "xrefs", None)
        return xrefs

    # Functions API

    def make_func(self, from_ea, to_ea_excl=None):
        f = self.get_addr_prop(from_ea, "fun_s")
        if f is not None:
            return f
        f = Function(from_ea, to_ea_excl)
        self.set_addr_prop(from_ea, "fun_s", f)

        if to_ea_excl is not None:
            self.set_addr_prop(to_ea_excl, "fun_e", f)
        return f

    def is_func(self, ea):
        return self.get_addr_prop(ea, "fun_s") is not None

    # If ea is start of function, return Function object
    def get_func_start(self, ea):
        return self.get_addr_prop(ea, "fun_s")

    # If ea is end of function, return Function object
    def get_func_end(self, ea):
        return self.get_addr_prop(ea, "fun_e")

    def set_func_end(self, func, ea):
        self.set_addr_prop(ea, "fun_e", func)

    # Look up function containing address
    def lookup_func(self, ea):
        # TODO: cache func ranges, use binary search instead
        for start, props in self.addr_map.items():
            func = props.get("fun_s")
            if func and ea >= start:
                end = func.get_end()
                if end is not None and ea < end:
                    return func

    # Issues API

    def add_issue(self, ea, descr):
        self.issues[ea] = descr

    def get_issues(self):
        res = []
        for ea in sorted(self.issues.keys()):
            res.append((ea, self.issues[ea]))
        return res

    # Persistence API

    def save_areas(self, stream):
        for a in self.area_list:
            stream.write("%08x %08x\n" % (a[START], a[END]))
            flags = a[FLAGS]
            i = 0
            while True:
                chunk = flags[i:i + 32]
                if not chunk:
                    break
                stream.write(str(binascii.hexlify(chunk), 'utf-8') + "\n")
                i += 32
            stream.write("\n")


    def save_addr_props(self, stream):
        stream.write("header:\n")
        stream.write(" version: 1.0\n")
        for addr, props in sorted(self.addr_map.items()):
                    # If entry has just fun_e data, skip it
                    if len(props) == 1 and "fun_e" in props:
                        continue
                    stream.write("0x%08x:\n" % addr)
                    fl = self.get_flags(addr)
                    stream.write(" f: %s %02x\n" % (flag2char(fl), fl))
                    label = props.get("label")
                    arg_props = props.get("args")
                    comm = props.get("comm")
                    xrefs = props.get("xrefs")
                    func = props.get("fun_s")
                    if label is not None:
                        if label == addr:
                            stream.write(" l:\n")
                        else:
                            stream.write(" l: %s\n" % label)
                    if arg_props is not None:
                        arg_props_header = False
                        for arg_no, data in sorted(arg_props.items()):
                            data = {k: v for k, v in data.items() if v is not None}
                            if data:
                                if not arg_props_header:
                                    stream.write(" args:\n")
                                    arg_props_header = True
                                stream.write("  %s: %r\n" % (arg_no, data))
                            #for k, v in sorted(data.items()):
                            #    stream.write("   %s: %s\n" % (k, v))
                    if comm is not None:
                        stream.write(" cmnt: %r\n" % comm)

                    if func is not None:
                        if func.end is not None:
                            stream.write(" fn_end: 0x%08x\n" % func.end)
                        else:
                            stream.write(" fn_end: '?'\n")
                        stream.write(" fn_ranges: [")
                        first = True
                        for r in func.get_ranges():
                            if not first:
                                stream.write(", ")
                            stream.write("[0x%08x,0x%08x]" % r)
                            first = False
                        stream.write("]\n")

                    if xrefs:
                        stream.write(" x:\n" % xrefs)
                        for from_addr in sorted(xrefs.keys()):
                            stream.write(" - 0x%08x: %s\n" % (from_addr, xrefs[from_addr]))

    def load_addr_props(self, stream):
        l = stream.readline()
        assert l == "header:\n"
        l = stream.readline()
        assert l == " version: 1.0\n"
        l = stream.readline()
        while l:
            assert l.endswith(":\n")
            addr = int(l[:-2], 0)
            props = self.addr_map.get(addr, {})
            l = stream.readline()
            while l and l[0] == " ":
                key, val = [x.strip() for x in l.split(":", 1)]
                l = None

                if key == "l":
                    if not val:
                        val = addr
                    props["label"] = val
                    self.labels_rev[val] = addr
                elif key == "cmnt":
                    props["comm"] = val[1:-1]
                elif key == "fn_end":
                    if val == "'?'":
                        end = None
                    else:
                        end = int(val, 0)
                    f = Function(addr, end)
                    props["fun_s"] = f
                    if end is not None:
                        self.addr_map[end] = {"fun_e": f}
                elif key == "fn_ranges":
                    if val != "[]":
                        assert val.startswith("[[") and val.endswith("]]"), val
                        val = val[2:-2]
                        f = props["fun_s"]
                        for r in val.split("], ["):
                            r = [int(x, 0) for x in r.split(",")]
                            f.add_range(*r)

                elif key == "args":
                    arg_props = {}
                    while True:
                        l = stream.readline()
                        if not l or not l.startswith("  "):
                            break
                        arg_no, data = [x.strip() for x in l.split(":", 1)]
                        assert data[0] == "{" and data[-1] == "}"
                        data = data[1:-1]
                        vals = {}
                        for pair in data.split(","):
                            seq = [x.strip() for x in pair.split(":", 1)]
                            for x in seq:
                                assert x[0] == "'" and x[-1] == "'", x
                            k, v = [x[1:-1] for x in seq]
                            vals[k] = v
                        arg_props[int(arg_no)] = vals
                    props["args"] = arg_props

                elif key == "x":
                    xrefs = {}
                    while True:
                        l = stream.readline()
                        if not l or not l.startswith(" - "):
                            break
                        key, val = [x.strip() for x in l[3:].split(":", 1)]
                        xrefs[int(key, 0)] = val
                    assert xrefs
                    props["xrefs"] = xrefs

                if l is None:
                    l = stream.readline()

            self.addr_map[addr] = props

    def load_areas(self, stream):
        for a in self.area_list:
            l = stream.readline()
            vals = [int(v, 16) for v in l.split()]
            assert a[START] == vals[0] and a[END] == vals[1]
            flags = a[FLAGS]
            i = 0
            while True:
                l = stream.readline().rstrip()
                if not l:
                    break
                l = binascii.unhexlify(l)
                flags[i:i + len(l)] = l
                i += len(l)


    # Hack for idaapi interfacing
    # TODO: should go to "Analysis" object
    def analisys_stack_push(self, ea, is_call=True):
        global analisys_stack_branches, analisys_stack_calls
        # If we know something is func (e.g. from loader), jump
        # to it means tail-call.
        if is_call or self.is_func(ea):
            analisys_stack_calls.append(ea)
        else:
            analisys_stack_branches.append(ea)


ADDRESS_SPACE = AddressSpace()
_processor = None
def set_processor(p):
    global _processor
    _processor = p
    idaapi.set_processor(p)


analisys_stack_calls = []
analisys_stack_branches = []

def add_entrypoint(ea, as_func=True):
    if as_func:
        ADDRESS_SPACE.make_func(ea, None)
        analisys_stack_calls.append(ea)
    else:
        analisys_stack_branches.append(ea)

def init_cmd(ea):
    _processor.cmd.ea = ea
    _processor.cmd.size = 0
    _processor.cmd.disasm = None

def finish_func(f):
    if f:
        log.info("Function %s (0x%x) ranges: %s" % (ADDRESS_SPACE.get_label(f.start), f.start, f.ranges.str(hex)))
        end = f.get_end()
        if end is not None:
            ADDRESS_SPACE.set_func_end(f, end)

def analyze(callback=lambda cnt:None):
    cnt = 0
    limit = 1000000
    current_func = None
    while limit:
        if analisys_stack_branches:
            ea = analisys_stack_branches.pop()
            fl = ADDRESS_SPACE.get_flags(ea, 0xff)
            if current_func:
                if fl == ADDRESS_SPACE.CODE | ADDRESS_SPACE.FUNC:
                    continue
                assert fl in (ADDRESS_SPACE.CODE, ADDRESS_SPACE.UNK)
            else:
                if fl != ADDRESS_SPACE.UNK:
                    continue
        elif analisys_stack_calls:
            finish_func(current_func)
            ea = analisys_stack_calls.pop()
            fun = ADDRESS_SPACE.get_func_start(ea)
            if fun.get_ranges():
                continue
            log.info("Starting analysis of function 0x%x" % ea)
            current_func = ADDRESS_SPACE.make_func(ea)
        else:
            finish_func(current_func)
            break
        init_cmd(ea)
        try:
            insn_sz = _processor.ana()
        except InvalidAddrException:
            # Ran out of memory area, just continue
            # with the rest of paths
            continue
#        print("size: %d" % insn_sz, _processor.cmd)
        if insn_sz:
            if not _processor.emu():
                assert False
            if current_func:
                current_func.add_insn(ea, insn_sz)
                ADDRESS_SPACE.make_code(ea, insn_sz, ADDRESS_SPACE.FUNC)
            else:
                ADDRESS_SPACE.make_code(ea, insn_sz)
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

    def __init__(self, target_addr=0, target_subno=0):
        self._lines = []
        self._cnt = 0
        self._subcnt = 0
        self._last_addr = -1
        self._addr2line = {}
        self.AS = None
        self.target_addr = target_addr
        self.target_subno = target_subno
        self.target_addr_lineno_0 = -1
        self.target_addr_lineno = -1
        self.target_addr_lineno_real = -1

    def lines(self):
        return self._lines

    def add_line(self, addr, line):
        if addr != self._last_addr:
            self._last_addr = addr
            self._subcnt = 0
        if addr == self.target_addr:
            if self._subcnt == 0:
                # Contains first line related to the given addr
                self.target_addr_lineno_0 = self._cnt
            if self._subcnt == self.target_subno:
                # Contains line no. target_subno related to the given addr
                self.target_addr_lineno = self._cnt
            if not line.virtual:
                # Contains line where actual instr/data/unknown bytes are
                # rendered (vs labels/xrefs/etc.)
                self.target_addr_lineno_real = self._cnt
        self._lines.append(line)
        self._addr2line[(addr, self._subcnt)] = self._cnt
        line.subno = self._subcnt
        if not line.virtual:
            # Line of "real" disasm object
            self._addr2line[(addr, -1)] = self._cnt
        self._cnt += 1
        self._subcnt += 1

    def addr2line_no(self, addr, subno=-1):
        return self._addr2line.get((addr, subno))

    def undefine_unit(self, addr):
        sz = self.AS.get_unit_size(addr)
        self.AS.make_undefined(addr, sz)


def data_sz2mnem(sz):
    s = {1: "db", 2: "dw", 4: "dd"}[sz]
    return idaapi.fillstr(s, idaapi.DEFAULT_WIDTH)


class DisasmObj:

    # Size of "leader fields" in disasm window - address, raw bytes, etc.
    # May be set by MVC controller
    LEADER_SIZE = 9

    # Default indent for a line
    indent = " " * idaapi.DEFAULT_INDENT

    # Default operand positions list is empty and set on class level
    # to save memory. To be overriden on object level.
    arg_pos = ()

    # If False, this object corresponds to real bytes in input binary stream
    # If True, doesn't correspond to bytes in memory: labels, etc.
    virtual = True

    # Textual comment to append
    comment = ""

    # Instance variable expected to be set on each instance:
    # ea =
    # size =
    # subno =  # relative no. of several lines corresponding to the same ea

    def render(self):
        # Render object as a string, set it as .cache, and return it
        pass

    def get_operand_addr(self):
        # Get "the most addressful" operand
        # This for example will be called when Enter is pressed
        # not on a specific instruction operand, so this should
        # return value of the operand which contains an address
        # (or the "most suitable" of them if there're few).
        return None

    def __len__(self):
        # Each object should return real character len as display on the screen.
        # Should be fast - called on each cursor movement.
        try:
            return self.LEADER_SIZE + len(self.indent) + len(self.cache)
        except AttributeError:
            return self.LEADER_SIZE + len(self.indent) + len(self.render())

    def content_len(self):
        return len(self) - (self.LEADER_SIZE + len(self.indent))


class Instruction(idaapi.insn_t, DisasmObj):

    virtual = False

    def render(self):
        _processor.cmd = self
        _processor.out()
        s = self.disasm + self.comment
        self.cache = s
        return s

    def get_operand_addr(self):
        # Assumes RISC design where only one operand can be address
        mem = imm = None
        for o in self._operands:
            if o.flags & idaapi.OF_SHOW:
                if o.type == idaapi.o_near:
                    # Jumps have priority
                    return o
                if o.type == idaapi.o_mem:
                    mem = o
                elif o.type == idaapi.o_imm:
                    imm = o
        if mem:
            return mem
        return imm

    def num_operands(self):
        for i, op in self._operands:
            if op.type == o_void:
                return i + 1
        return UA_MAXOP


class Data(DisasmObj):

    virtual = False

    def __init__(self, ea, sz, val):
        self.ea = ea
        self.size = sz
        self.val = val

    def render(self):
        subtype = ADDRESS_SPACE.get_arg_prop(self.ea, 0, "subtype")
        if subtype == IMM_ADDR:
            label = self.val
            if not isinstance(label, str):
                label = ADDRESS_SPACE.get_label(label)
            s = "%s%s" % (data_sz2mnem(self.size), label)
        else:
            s = "%s0x%x" % (data_sz2mnem(self.size), self.val)
        s += self.comment
        self.cache = s
        return s

    def get_operand_addr(self):
        o = idaapi.op_t(0)
        o.value = self.val
        o.addr = self.val
        o.type = idaapi.o_imm
        return o


class String(DisasmObj):

    virtual = False

    def __init__(self, ea, sz, val):
        self.ea = ea
        self.size = sz
        self.val = val

    def render(self):
        s = "%s%s" % (data_sz2mnem(1), repr(self.val).replace("\\x00", "\\0"))
        s += self.comment
        self.cache = s
        return s


class Fill(DisasmObj):

    virtual = False

    def __init__(self, ea, sz):
        self.ea = ea
        self.size = sz
        self.cache = idaapi.fillstr(".fill", idaapi.DEFAULT_WIDTH) + str(sz)

    def render(self):
        return self.cache


class Unknown(DisasmObj):

    virtual = False
    size = 1

    def __init__(self, ea, val):
        self.ea = ea
        self.val = val

    def render(self):
        ch = ""
        if 0x20 <= self.val <= 0x7e:
            ch = " ; '%s'" % chr(self.val)
        s = "%s0x%02x%s" % (idaapi.fillstr("unk", idaapi.DEFAULT_WIDTH), self.val, ch)
        s += self.comment
        self.cache = s
        return s


class Label(DisasmObj):

    indent = ""

    def __init__(self, ea):
        self.ea = ea

    def render(self):
        label = ADDRESS_SPACE.get_label(self.ea)
        s = "%s:" % label
        self.cache = s
        return s


class Xref(DisasmObj):

    indent = ""

    def __init__(self, ea, from_addr, type):
        self.ea = ea
        self.from_addr = from_addr
        self.type = type

    def render(self):
        s = (" " * idaapi.DEFAULT_XREF_INDENT) + "; xref: 0x%x %s" % (self.from_addr, self.type)
        self.cache = s
        return s

    def get_operand_addr(self):
        o = idaapi.op_t(0)
        o.addr = self.from_addr
        return o


class Literal(DisasmObj):

    indent = ""

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

def render_partial_around(addr, subno, context_lines):
    log.debug("render_partial_around(%x, %d)", addr, subno)
    off, area = ADDRESS_SPACE.addr2area(addr)
    if area is None:
        return None
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
    log.debug("render_partial_around: off=0x%x, %s", off, str_area(area))
    off = ADDRESS_SPACE.adjust_offset_reverse(off, area)
    log.debug("render_partial_around adjusted: off=0x%x, %s", off, str_area(area))
    model = Model(addr, subno)
    render_partial(model, ADDRESS_SPACE.area_list.index(area), off, context_lines, addr)
    log.debug("render_partial_around model done, lines: %d", len(model.lines()))
    assert model.target_addr_lineno_0 >= 0
    if model.target_addr_lineno == -1:
        # If we couldn't find exact subno, use 0th subno of that addr
        # TODO: maybe should be last subno, because if we couldn't find
        # exact one, it was ~ last and removed, so current last is "closer"
        # to it.
        model.target_addr_lineno = model.target_addr_lineno_0
    return model


def render_from(model, addr, num_lines):
    off, area = ADDRESS_SPACE.addr2area(addr)
    if area is None:
        return None
    return render_partial(model, ADDRESS_SPACE.area_list.index(area), off, num_lines)


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
        if i == 0:
            model.add_line(a[START], Literal(a[START], "; Start of 0x%x area (%s)" % (a[START], a[PROPS].get("name", "noname"))))
        bytes = a[BYTES]
        flags = a[FLAGS]
        areasize = len(bytes)
        while i < areasize:
            addr = a[START] + i
            # If we didn't yet reach target address, compensate for
            # the following decrement of num_lines. The logic is:
            # render all lines up to target_addr, and then num_lines past it.
            if target_addr >= 0 and addr < target_addr:
                num_lines += 1

            props = ADDRESS_SPACE.get_addr_prop_dict(addr)
            func = props.get("fun_s")
            if func:
                model.add_line(addr, Literal(addr, "; Start of '%s' function" % ADDRESS_SPACE.get_label(func.start)))

            xrefs = props.get("xrefs")
            if xrefs:
                for from_addr in sorted(xrefs.keys()):
                    model.add_line(addr, Xref(addr, from_addr, xrefs[from_addr]))

            label = props.get("label")
            if label:
                model.add_line(addr, Label(addr))

            f = flags[i] & 0x7f
            if f == AddressSpace.UNK:
                out = Unknown(addr, bytes[i])
                sz = 1
                i += 1
            elif f & AddressSpace.DATA:
                sz = 1
                j = i + 1
                while j < areasize and flags[j] & AddressSpace.DATA_CONT:
                    sz += 1
                    j += 1
                assert sz <= 4
                out = Data(addr, sz, ADDRESS_SPACE.get_data(addr, sz))
                i += sz
            elif f == AddressSpace.STR:
                str = chr(bytes[i])
                sz = 1
                j = i + 1
                while j < areasize and flags[j] == AddressSpace.DATA_CONT:
                    str += chr(bytes[j])
                    sz += 1
                    j += 1
                out = String(addr, sz, str)
                i += sz
            elif f == AddressSpace.FILL:
                sz = 1
                j = i + 1
                while j < areasize and flags[j] == AddressSpace.FILL:
                    sz += 1
                    j += 1
                out = Fill(addr, sz)
                i += sz
            elif f == AddressSpace.CODE:
                out = Instruction(addr)
                _processor.cmd = out
                sz = _processor.ana()
                _processor.out()
                i += sz
            else:
                model.add_line(addr, Literal(addr, "; UNEXPECTED value: %02x flags: %02x" % (bytes[i], f)))
                sz = 1
                i += 1
                assert 0, "@%08x flags=%x" % (addr, f)

            comm = props.get("comm")
            if comm:
                comm_indent = " " * (out.content_len() + len(out.indent) + 2)
                out.comment = "  ; " + comm.split("|", 1)[0]

            model.add_line(addr, out)
            #sys.stdout.write(out + "\n")

            if comm:
                for comm_l in comm.split("|")[1:]:
                    comm_obj = Literal(addr, "; " + comm_l)
                    comm_obj.indent = comm_indent
                    model.add_line(addr, comm_obj)

            next_addr = addr + sz
            next_props = ADDRESS_SPACE.get_addr_prop_dict(next_addr)
            func_end = next_props.get("fun_e")
            if func_end:
                model.add_line(addr, Literal(addr, "; End of '%s' function (%s)" % (
                    ADDRESS_SPACE.get_label(func_end.start), func_end.get_end_method()
                )))

            num_lines -= 1
            if not num_lines:
                return next_addr

        model.add_line(a[END], Literal(a[END], "; End of 0x%x area (%s)" % (a[START], a[PROPS].get("name", "noname"))))


def flag2char(f):
    if f == AddressSpace.UNK:
        return "."
    elif f == AddressSpace.CODE:
        return "C"
    elif f == AddressSpace.CODE | AddressSpace.FUNC:
        return "F"
    elif f == AddressSpace.CODE_CONT:
        return "c"
    elif f == AddressSpace.DATA:
        return "D"
    elif f == AddressSpace.DATA_CONT:
        return "d"
    elif f == AddressSpace.STR:
        return "A"
    elif f == AddressSpace.FILL:
        return "-"
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
idc.set_address_space(ADDRESS_SPACE)
