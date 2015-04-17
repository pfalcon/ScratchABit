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
from idaapi import *
from pymsasid3 import pymsasid


class IDAPythonSource(pymsasid.Hook):

    entry_point = 0

    def __init__(self, source, base_address):
        super().__init__(source, base_address)
        self.ea = source
        self.pos = 0

    def hook(self):
        b = get_full_byte(self.ea + self.pos)
        self.pos += 1
        return b


class X86Processor(processor_t):

    def __init__(self, bitness):
        super().__init__()
        self.bitness = bitness

    def ana(self):
        #print("ana: %x" % self.cmd.ea)
        dis = pymsasid.Pymsasid(source=self.cmd.ea, hook=IDAPythonSource)
        dis.dis_mode = self.bitness

        inst = dis.decode()
        #print(inst, inst.operand)

        # Reset operands in a static cmd object
        for i in range(UA_MAXOP):
            self.cmd[i].type = o_void

        # Convert pymsasid operands to IDAPython operands
        # (here only minimal conversion is implemented:
        # for immediate values, any of which may be actually
        # address, and for jumps, which are required for
        # control flow discovery)
        for i, op in enumerate(inst.operand):
            if op.type == "OP_IMM":
                self.cmd[i].type = o_imm
                assert isinstance(op.lval, int)
                self.cmd[i].value = op.lval
            elif op.type == "OP_JIMM":
                self.cmd[i].type = o_near
                self.cmd[i].addr = self.cmd.ea + inst.size + op.lval
            else:
                # Uninterpreted
                self.cmd[i].type = o_idpspec0
                self.cmd[i].specval = op

        self.cmd.size = inst.size
        self.cmd.inst = inst
        return self.cmd.size

    def emu(self):
        #print("emu: %s" % self.cmd)
        inst = self.cmd.inst
        flow = inst.flow_label()
        for i in range(UA_MAXOP):
            op = self.cmd[i]
            if op.type == o_void:
                break
            elif op.type == o_near:
                if flow == "call":
                    ua_add_cref(0, op.addr, fl_CN)
                else:
                    ua_add_cref(0, op.addr, fl_JN)

        if flow in ("call", "jcc", "hlt", "seq"):
            ua_add_cref(0, self.cmd.ea + self.cmd.size, fl_F)

        return True

    def outop(self, op):
        if op.type == o_imm:
            OutValue(op, OOFW_IMM)
        elif op.type in (o_near, o_mem):
            ok = out_name_expr(op, op.addr, BADADDR)
            if not ok:
                out_tagon(COLOR_ERROR)
                OutLong(op.addr, 16)
                out_tagoff(COLOR_ERROR)
                QueueMark(Q_noName, self.cmd.ea)
        elif op.type == o_idpspec0:
            OutLine(str(op.specval))
        else:
            return False
        return True

    def out(self):
        buf = init_output_buffer(1024)
        inst = self.cmd.inst

        # Normally should use OutMnem, but as we don't maintain
        # processor_t.instruc, output manually
        OutLine(fillstr(inst.operator, 8))

        for i in range(UA_MAXOP):
            if self.cmd[i].type == o_void:
                break

            if self.cmd[i].flags & OF_SHOW == 0:
                continue

            if i > 0:
                out_symbol(',')
            OutChar(' ')
            out_one_operand(i)

        cvar.gl_comm = 1
        MakeLine(buf)
