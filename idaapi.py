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
from io import StringIO
import logging as log

from scratchabit import defs


# Data types
dt_byte = "dt_byte"
dt_word = "dt_word"
dt_dword = "dt_dword"
DATA_SIZE = {dt_byte: 1, dt_word: 2, dt_dword: 4}

# IDA standard 6
UA_MAXOP = 6

# Operand types
o_void = "-"
# Immediate value, can be either numeric value, or address of memory
# ("offset"), further differentiated by value subtype (offset, hex, dec, etc.)
o_imm = "o_imm"
o_reg = "o_reg"
# Location in memory. Should be used only if instruction guaranteedly
# access memory at the given address of the given size (direct addressing
# mode). Should not be mixed up with o_imm of offset subtype.
o_mem = "o_mem"
o_near = "o_near"
o_phrase = "o_phrase"
o_displ = "o_displ"
o_idpspec0 = "o_idpspec0"

class BADADDR: pass

# Processor flags
PR_SEGS = 1
PR_DEFSEG32 = 2
PR_RNAMESOK = 4
PR_ADJSEGS = 8
PRN_HEX = 16
PR_USE32 = 32

# Assembler syntax flags
ASH_HEXF3 = 1
ASD_DECF0 = 2
ASO_OCTF1 = 4
ASB_BINF3 = 8
AS_NOTAB = 16
AS_ASCIIC = 32
AS_ASCIIZ = 64

# Operand flags (op_t.flags)
OF_SHOW = 0x08  # If not set, operand is not shown

# Operand/value output flags (OutValue, etc.)
OOFS_IFSIGN = 0
OOFS_NOSIGN = 1
OOFS_NEEDSIGN = 2
OOF_SIGNED = 4
OOF_NUMBER = 8
OOFW_IMM = 0
OOFW_16 = 0x10
OOFW_32 = 0x20
OOFW_8  = 0x30
OOF_ADDR = 0x40

# Basic instruction semantics ("features" is IDA-speak)
CF_CALL = 1
CF_STOP = 2  # Control flow stops here, e.g. jump, ret
CF_JUMP = 4  # Not just a jump, indirect jump (or call)!

# Code references (i.e. control flow flags)
fl_CN = 1  # "call near"
fl_JN = 2  # "jump near"
fl_F = 3   # "ordinary flow"
# ScratchABit extensions:
# Return address from a call. Next instruction from a call, whenever possible,
# Should use this flag instead of fl_F. This is because there's no guarantee
# that a call will return, so such code paths need to be treated with different
# priority than "next instruction" and "jump" code paths.
fl_RET_FROM_CALL = 10
# Sane names
fl_CALL = fl_CN
fl_JUMP = fl_JN

# Data references
dr_R = "r"
dr_W = "w"
dr_O = "o"  # "Offset" reference, address of an item is taken

# Segment permissions
SEGPERM_EXEC  = 1
SEGPERM_WRITE = 2
SEGPERM_READ  = 4


class cvar:
    pass

class op_t:

    def __init__(self, no):
        self.n = no
        self.type = None
        self.flags = OF_SHOW

    def get_addr(self):
        if hasattr(self, "addr"):
            return self.addr
        if hasattr(self, "value"):
            return self.value
        return None

    def __repr__(self):
        #return str(self.__dict__)
        return "op_t(#%d, t=%s, addr/val=%s)" % (self.n, self.type, self.get_addr())

class insn_t:

    def __init__(self, ea=0):
        self.ea = ea
        self.size = 0
        self.itype = 0
        self._operands = [op_t(i) for i in range(UA_MAXOP)]
        self.disasm = None

    def get_canon_feature(self):
        return _processor.instruc[self.itype]["feature"]

    def __getitem__(self, i):
        return self._operands[i]

    # ScratchABit extension
    def num_operands(self):
        for i, op in enumerate(self._operands):
            if op.type == o_void:
                return i
        return UA_MAXOP

    def __repr__(self):
        #return "insn_t(ea=%x, sz=%d, id=%d, %r, %s)" % (self.ea, self.size, self.itype, self.disasm, self._operands)
        used_operands = self._operands[0:self.num_operands()]
        return "insn_t(ea=%x, sz=%d, id=%d, %r, %s)" % (self.ea, self.size, self.itype, self.disasm, used_operands)


class processor_t:
    def __init__(self):
        self.cmd = cmd


#
# Instruction rendition API ("out()" in IDA-speak)
#

COLOR_ERROR = "*"
# Non-IDAPython symbols
# Default instruction field width, 8 is IDA standard
DEFAULT_WIDTH = 8
# Default indentation of instructions
DEFAULT_INDENT = 4
# Default indentation of xref comments
DEFAULT_XREF_INDENT = 13

u_line = None

def init_output_buffer(n):
    global u_line
    u_line = StringIO()
    return u_line

def term_output_buffer():
    pass

def fillstr(s, width):
    if len(s) < width:
        s += " " * (width - len(s))
    return s

def OutMnem(width=DEFAULT_WIDTH):
    global _processor, u_line
#    print(_processor.instruc[cmd.itype])
    s = _processor.instruc[_processor.cmd.itype]["name"]
    u_line.write(fillstr(s, width))

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
    cmd = _processor.cmd

    # Init array of this operand's positions in output line
    if not hasattr(cmd, "arg_pos") or not cmd.arg_pos:
        cmd.arg_pos = [[0, 0] for i in range(UA_MAXOP)]

    op = cmd[op_no]
    op.props = ADDRESS_SPACE.get_arg_prop_dict(cmd.ea, op_no)

    # Record start position of this operand in output line
    cmd.arg_pos[op_no][0] = len(u_line.getvalue())

    _processor.outop(op)

    # Record end position of this operand in output line
    cmd.arg_pos[op_no][1] = len(u_line.getvalue())


def OutValue(op, flags):
    global u_line
#    print(op, flags)
    if flags & OOF_ADDR:
        val = op.addr
    else:
        val = op.value
    # Undefined symbol value
    if isinstance(val, str):
        u_line.write(val)
        return
    subtype = op.props.get("subtype")
    if subtype == defs.IMM_ADDR:
        out_name_expr(op, val, BADADDR)
    elif subtype == defs.IMM_UDEC:
        u_line.write(str(val))
    else:
        u_line.write(hex(val))

def OutLong(val, base):
    global u_line
    if base == 2:
        u_line.write(bin(val))
    elif base == 8:
        u_line.write(oct(val))
    elif base == 10:
        u_line.write(str(val))
    elif base == 16:
        u_line.write(hex(val))
    else:
        raise NotImplementetError

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

def out_tagoff(tag):
    pass

def out_register(reg):
    OutLine(reg)

def MakeLine(output_buffer):
#    global cmd
    global _processor
    _processor.cmd.disasm = output_buffer.getvalue().rstrip()

#
# End of instruction rendition API
#

#
# Address space access API
#

def get_full_byte(ea):
    return ADDRESS_SPACE.get_byte(ea)

# Extension
def get_full_val(ea, val_sz):
    return ADDRESS_SPACE.get_data(ea, val_sz)

def ua_add_cref(opoff, ea, flags):
    ADDRESS_SPACE.analisys_stack_push(ea, flags)
    if flags == fl_JN:
        ADDRESS_SPACE.make_auto_label(ea)
        ADDRESS_SPACE.add_xref(_processor.cmd.ea, ea, "j")
    elif flags == fl_CN:
        ADDRESS_SPACE.make_label("fun_", ea)
        ADDRESS_SPACE.add_xref(_processor.cmd.ea, ea, "c")
        fl = ADDRESS_SPACE.get_flags(ea, 0xff)
        if fl & ADDRESS_SPACE.FUNC:
            if not ADDRESS_SPACE.is_func(ea):
                log.warn("Address 0x%x calls inside another function: 0x%x", _processor.cmd.ea, ea)
        ADDRESS_SPACE.make_func(ea, None)


def ua_dodata2(opoff, ea, dtype):
#    print(opoff, hex(ea), dtype)
#    address_map[ea] = {"type": type, "access": set()}
    ADDRESS_SPACE.make_data(ea, DATA_SIZE[dtype])
    ADDRESS_SPACE.make_auto_label(ea)

def ua_add_dref(opoff, ea, access):
    ADDRESS_SPACE.add_xref(_processor.cmd.ea, ea, access)
    pass

Q_jumps = 1
Q_noName = 2

def QueueMark(type, ea):
    if type == Q_jumps:
        ADDRESS_SPACE.add_issue(ea, "Indirect jump")
    elif type == Q_noName:
        ADDRESS_SPACE.add_issue(ea, "Ref to address outside address space")
    else:
        assert 0

#
# End of Address space access API
#

#
# Instruction operands API
#

REF_OFF32 = 2

# TODO: ref_addr is extension
def op_offset(ea, op_no, reftype, ref_addr):
    ADDRESS_SPACE.make_arg_offset(ea, op_no, ref_addr)

def is_offset(ea, op_no):
    return ADDRESS_SPACE.get_arg_prop(ea, op_no, "subtype") == defs.IMM_ADDR


#
# End of Instruction operands API
#

#
# Comment API
# Note that repeating comments are not supported, so the "repeating" argument
# is ignored
#

def set_cmt(ea, cmt, repeating):
    ADDRESS_SPACE.set_comment(ea, cmt)

def get_cmt(ea, repeating):
    return ADDRESS_SPACE.get_comment(ea)

#
# End of Comment API
#



# Interfacing

# "cmd is a global variable of type insn_t. It is contains information
# about the last decoded instruction. This variable is also filled by
# processor modules when they decode instructions."
cmd = insn_t()

_processor = None

def set_processor(p):
    global _processor
    _processor = p

ADDRESS_SPACE = None

def set_address_space(aspace):
    global ADDRESS_SPACE
    ADDRESS_SPACE = aspace
