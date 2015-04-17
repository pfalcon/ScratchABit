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

import engine


# Data types
dt_byte = "dt_byte"
dt_word = "dt_word"
dt_dword = "dt_dword"
DATA_SIZE = {dt_byte: 1, dt_word: 2, dt_dword: 4}

# IDA standard 6
UA_MAXOP = 6

# Operand types
o_void = "-"
o_imm = "o_imm"
o_reg = "o_reg"
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

    def __repr__(self):
        #return str(self.__dict__)
        return "insn_t(ea=%x, sz=%d, id=%d, %s, %s)" % (self.ea, self.size, self.itype, self.disasm, self._operands)


class processor_t:
    def __init__(self):
        self.cmd = cmd


#
# Instruction rendition API ("out()" in IDA-speak)
#

COLOR_ERROR = "*"

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

DEFAULT_WIDTH = 16

def OutMnem(width):
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

    if not hasattr(cmd, "arg_pos") or not cmd.arg_pos:
        cmd.arg_pos = [[0, 0] for i in range(UA_MAXOP)]
    cmd.arg_pos[op_no][0] = len(u_line.getvalue())

    op = cmd[op_no]
    patched = False
    if op.type == o_imm:
        if ADDRESS_SPACE.get_arg_prop(cmd.ea, op_no, "type") == o_mem:
            # if native operand type is immediate value, but it was overriden to be
            # address/offset, it should be output as such
            op.addr = op.value
            op.type = o_mem
            patched = True

    _processor.outop(op)
    if patched:
        op.type = o_imm
    cmd.arg_pos[op_no][1] = len(u_line.getvalue())


def OutValue(op, flags):
    global u_line
#    print(op, flags)
    u_line.write(hex(op.value))

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

def MakeLine(output_buffer):
#    global cmd
    global _processor
    _processor.cmd.disasm = output_buffer.getvalue()

#
# End of instruction rendition API
#

#
# Address space access API
#

def get_full_byte(ea):
    return ADDRESS_SPACE.get_byte(ea)

def ua_add_cref(opoff, ea, flags):
    try:
        fl = ADDRESS_SPACE.get_flags(ea)
    except engine.InvalidAddrException:
        log.warning("ua_add_cref: Cannot get flags for %x - not adding cref", ea)
        return
    if fl == ADDRESS_SPACE.UNK:
        ADDRESS_SPACE.analisys_stack_push(ea)
    else:
        assert fl == ADDRESS_SPACE.CODE
    if flags == fl_JN:
        ADDRESS_SPACE.make_auto_label(ea)
        ADDRESS_SPACE.add_xref(_processor.cmd.ea, ea, "j")
    elif flags == fl_CN:
        ADDRESS_SPACE.make_label("fun_", ea)
        ADDRESS_SPACE.add_xref(_processor.cmd.ea, ea, "c")


def ua_dodata2(opoff, ea, dtype):
#    print(opoff, hex(ea), dtype)
#    address_map[ea] = {"type": type, "access": set()}
    ADDRESS_SPACE.note_data(ea, DATA_SIZE[dtype])
    ADDRESS_SPACE.make_auto_label(ea)

def ua_add_dref(opoff, ea, access):
    ADDRESS_SPACE.add_xref(_processor.cmd.ea, ea, access)
    pass

#
# End of Address space access API
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
