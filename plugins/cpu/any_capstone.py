# ScratchABit - interactive disassembler
#
# Copyright (c) 2018 Paul Sokolovsky
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
from capstone import *
from idaapi import *


# Custom group to extend Capstone's
CS_GRP_JUMP_UNCOND = -100


# Split operand string by commas, taking into account that operands may
# contain commas too.
# This works around Capstone's inability to render individual instruction
# operands: https://github.com/aquynh/capstone/issues/1069
def parse_operands(s):
    need_comma = False
    while True:
        s = s.lstrip()
        if not s:
            break
        if s.startswith(","):
            s = s[1:].lstrip()
        if s.startswith("["):
            i = s.find("]")
            yield s[0:i + 1]
            s = s[i + 1:]
        else:
            i = s.find(",")
            if i == -1:
                i = len(s)
            yield s[0:i].rstrip()
            s = s[i:]


class Processor(processor_t):

    def __init__(self, md):
        super().__init__()
        md.detail = True
        self.md = md

    # TODO: factor out
    def outop(self, op):
        if op.type == o_reg:
            out_register(op.value)
        elif op.type == o_imm:
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


    @staticmethod
    def patch_capstone_groups(inst):
        # Workarounds for Capstone under-classifying instructions:
        # https://github.com/aquynh/capstone/issues/1072
        groups = set(inst.groups)
        if 1: #ARM
            if inst.mnemonic in ("bl", "blx"):
                groups.add(CS_GRP_CALL)
            elif inst.mnemonic in ("b", "bx"):
                groups.add(CS_GRP_JUMP_UNCOND)
            elif inst.mnemonic.startswith(("ldmia", "pop")) and "pc" in inst.op_str:
                # LDMIA aka POP on ARM can be used for return
                groups.add(CS_GRP_RET)
        if 2: # x86
            if inst.mnemonic == "jmp":
                groups.add(CS_GRP_JUMP_UNCOND)
        return groups


    def ana(self):
        ea = self.cmd.ea
        #print("ana: %x" % ea)
        while True:
            data = get_bytes(ea, 16)
            res = list(self.md.disasm(bytes(data), ea, count=1))
            if res:
                break
            #assert False, "Cannot disasm @0x%x" % ea
            return

        inst = res[0]
        groups = self.patch_capstone_groups(inst)
        #print(inst.mnemonic, inst.op_str, "sz:", inst.size)
        #print("groups:", groups)

        # Reset operands in a static cmd object
        for i in range(UA_MAXOP):
            self.cmd[i].type = o_void

        is_jumpcall = CS_GRP_JUMP in groups or CS_GRP_CALL in groups

        op_strs = list(parse_operands(inst.op_str))
        #print(inst.operands, op_strs)

        for i, op in enumerate(inst.operands):
            #print(i, op, op.type, op.value)
            if op.type == CS_OP_REG:
                self.cmd[i].type = o_reg
                self.cmd[i].value = inst.reg_name(op.value.reg)
            elif op.type == CS_OP_IMM:
                if is_jumpcall:
                    self.cmd[i].type = o_near
                    self.cmd[i].addr = op.value.imm
                else:
                    self.cmd[i].type = o_imm
                    self.cmd[i].value = op.value.imm
            #elif op.type == CS_OP_MEM:
            #    print(str(op), repr(op), dir(op), op.mem)
            else:
                # Uninterpreted
                self.cmd[i].type = o_idpspec0
                self.cmd[i].specval = op_strs[i]

        self.cmd.size = inst.size
        self.cmd.inst = inst
        self.cmd.inst_groups = groups
        return self.cmd.size

    def emu(self):
        inst = self.cmd.inst
        is_jump = CS_GRP_JUMP in self.cmd.inst_groups
        is_jump_uncond = CS_GRP_JUMP_UNCOND in self.cmd.inst_groups
        is_call = CS_GRP_CALL in self.cmd.inst_groups
        is_ret = CS_GRP_RET in self.cmd.inst_groups or CS_GRP_IRET in self.cmd.inst_groups

        for i in range(UA_MAXOP):
            op = self.cmd[i]
            if op.type == o_void:
                break
            elif op.type == o_near:
                if is_call:
                    ua_add_cref(0, op.addr, fl_CN)
                else:
                    ua_add_cref(0, op.addr, fl_JN)

        if not is_jump_uncond and not is_ret:
            ua_add_cref(0, self.cmd.ea + self.cmd.size, fl_F)

        return True

    def out(self):
        buf = init_output_buffer(1024)
        inst = self.cmd.inst

        # Normally should use OutMnem, but as we don't maintain
        # processor_t.instruc, output manually
        OutLine(fillstr(inst.mnemonic, 8))

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
