# IDAPython ARM Thumb processor module
#
# Copyright (C) 2014 Fredrik Ahlberg
# Copyright (C) 2017 Damien P. George
# Copyright (C) 2017 Rami Ali
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful, but WITHOUT 
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
# Street, Fifth Floor, Boston, MA 02110-1301 USA.

from idaapi import *

o_reglist = 'o_reglist'

# If set to 1, use "sp" register name for "a1"
SPECIAL_NAMES = 1

HELP = 'arm-thumb'

REG_SP = 13
REG_LR = 14
REG_PC = 15

class Operand:
    REG    = 0
    IMM    = 1
    REL    = 2
    REG_LIST = 3

    def __init__(self, type, size, rshift, size2 = 0, rshift2 = 0, vshift = 0, off = 0, signbit = 0, bw = None):
        self.type = type
        self.size = size
        self.rshift = rshift
        self.size2 = size2
        self.rshift2 = rshift2
        self.vshift = vshift
        self.off = off
        self.signbit = signbit
        self.bw = bw


    def bitfield(self, op, size, rshift):
        val = (op >> rshift) & (0xffffffff >> (32 - size))
        return val

    def parse(self, ret, op, cmd = None):
        val = self.bitfield(op, self.size, self.rshift)
        if self.size2:
            val |= self.bitfield(op, self.size2, self.rshift2) << self.size

        val <<= self.vshift
        val += self.off

        if self.type == Operand.REG:
            ret.type = o_reg
            ret.reg = val
        elif self.type == Operand.IMM:
            ret.type = o_imm
            ret.value = val
        elif self.type == Operand.REG_LIST:
            ret.type = o_reglist
            ret.reglist = val
        elif self.type == Operand.REL:
            ret.type = o_near
            if self.bw == 1:
                val0 = val >> 16
                s = val >> 10 & 0x1
                j1 = val0 >> 13 & 0x1
                j2 = val0 >> 11 & 0x1
                off = (val0 & 0x7ff) << 1
                off = off | (val & 0x3f) << 12
                off = off | j1 << 18
                off = off | j2 << 19
                off = off | s << 20
                ret.addr = cmd.ea + 4 + off
            elif self.bw == 2:
                val0 = val >> 16
                s = val >> 10 & 0x1
                j1 = val0 >> 13 & 0x1
                j2 = val0 >> 11 & 0x1
                off = (val0 & 0x7ff) << 1
                off = off | (val & 0x3ff) << 12
                off = off | (~(j2 ^ s) & 1) << 22
                off = off | (~(j1 ^ s) & 1) << 23
                off = off | s << 24
                ret.addr = cmd.ea + 4 + off
            else:
                if self.signbit != 0 and val & 0x1 << (self.signbit + self.vshift - 1):
                    val -= 1 << (self.signbit + self.vshift)
                ret.addr = val + cmd.ea + 4
        else:
            raise ValueError("unhandled operand type");

class Instr(object):
    fmt_THUMB_1 = (2, (Operand(Operand.REG, 3, 0), Operand(Operand.REG, 3, 3), Operand(Operand.IMM, 5, 6)))
    fmt_THUMB_2 = (2, (Operand(Operand.REG, 3, 0), Operand(Operand.REG, 3, 3), Operand(Operand.REG, 3, 6)))
    fmt_THUMB_2_IMM = (2, (Operand(Operand.REG, 3, 0), Operand(Operand.REG, 3, 3), Operand(Operand.IMM, 3, 6)))
    fmt_THUMB_3 = (2, (Operand(Operand.REG, 3, 8), Operand(Operand.IMM, 8, 0)))
    fmt_THUMB_4 = (2, (Operand(Operand.REG, 3, 0), Operand(Operand.REG, 3, 3)))
    fmt_THUMB_5 = (2, (Operand(Operand.REG, 3, 0, 1, 7), Operand(Operand.REG, 4, 3)))
    fmt_THUMB_5_BX = (2, (Operand(Operand.REG, 4, 3),))
    fmt_THUMB_6 = (2, (Operand(Operand.REG, 3, 8), Operand(Operand.REG, 0, 0, off=REG_PC), Operand(Operand.IMM, 8, 0, vshift=2)))
    fmt_THUMB_7 = (2, (Operand(Operand.REG, 3, 0), Operand(Operand.REG, 3, 3), Operand(Operand.REG, 3, 6)))
    fmt_THUMB_8 = (2, (Operand(Operand.REG, 3, 0), Operand(Operand.REG, 3, 3), Operand(Operand.REG, 3, 6)))
    fmt_THUMB_9 = (2, (Operand(Operand.REG, 3, 0), Operand(Operand.REG, 3, 3), Operand(Operand.IMM, 5, 6, vshift=2)))
    fmt_THUMB_9_B = (2, (Operand(Operand.REG, 3, 0), Operand(Operand.REG, 3, 3), Operand(Operand.IMM, 5, 6)))
    fmt_THUMB_10 = (2, (Operand(Operand.REG, 3, 0), Operand(Operand.REG, 3, 3), Operand(Operand.IMM, 5, 6, vshift=1)))
    fmt_THUMB_11 = (2, (Operand(Operand.REG, 3, 8), Operand(Operand.REG, 0, 0, off=REG_SP), Operand(Operand.IMM, 8, 0, vshift=2)))
    fmt_THUMB_12 = (2, (Operand(Operand.REG, 3, 8), Operand(Operand.REG, 0, 0, off=REG_PC), Operand(Operand.IMM, 8, 0, vshift=2)))
    fmt_THUMB_12_SP = (2, (Operand(Operand.REG, 3, 8), Operand(Operand.REG, 0, 0, off=REG_SP), Operand(Operand.IMM, 8, 0, vshift=2)))
    fmt_THUMB_13 = (2, (Operand(Operand.REG, 0, 0, off=REG_SP), Operand(Operand.IMM, 7, 0, vshift=2)))
    fmt_THUMB_14 = (2, (Operand(Operand.REG_LIST, 8, 0),))
    fmt_THUMB_14_LR = (2, (Operand(Operand.REG_LIST, 8, 0), Operand(Operand.REG, 0, 0, off=REG_LR)))
    fmt_THUMB_14_PC = (2, (Operand(Operand.REG_LIST, 8, 0), Operand(Operand.REG, 0, 0, off=REG_PC)))
    fmt_THUMB_15 = (2, (Operand(Operand.REG, 3, 8), Operand(Operand.REG_LIST, 8, 0)))
    fmt_THUMB_16 = (2, (Operand(Operand.REL, 8, 0, vshift=1, signbit=8),))
    fmt_THUMB_17 = (2, (Operand(Operand.IMM, 8, 0),))
    fmt_THUMB_18 = (2, (Operand(Operand.REL, 11, 0, vshift=1, signbit=11),))
    fmt_THUMB_19 = (4, (Operand(Operand.REL, 11, 16, 11, 0, vshift=1, signbit=22),))
    fmt_THUMB2_RRL = (4, (Operand(Operand.REG, 4, 0), Operand(Operand.REG_LIST, 16, 16)))
    fmt_THUMB2_RRI8 = (4, (Operand(Operand.REG, 4, 24), Operand(Operand.REG, 4, 0), Operand(Operand.IMM, 8, 16)))
    fmt_THUMB2_RRI12 = (4, (Operand(Operand.REG, 4, 28), Operand(Operand.REG, 4, 0), Operand(Operand.IMM, 12, 16)))
    fmt_THUMB2_N1 = (4, (Operand(Operand.REL, 32, 0, bw=1),))
    fmt_THUMB2_N2 = (4, (Operand(Operand.REL, 32, 0, bw=2),))

    def __init__(self, name, opcode, mask, fmt, flags = 0):
        self.name = name
        self.opcode = opcode
        self.mask = mask
        (self.size, self.fmt) = fmt
        self.flags = flags
        
    def match(self, op):
        return (op & self.mask) == self.opcode

    def parseOperands(self, operands, op, cmd = None):
        if isinstance(self.fmt, tuple):
            for i, o in enumerate(self.fmt):
                o.parse(operands[i], op, cmd)
            return
        if self.fmt is None:
            return

    def __str__(self):
        return "<Instr %s %x/%x>" % (self.name, self.opcode, self.mask)

class ArmProcessor(processor_t):
    regPrefix = ""

    ops = (
        ("lsl", 0x0000, 0xf800, Instr.fmt_THUMB_1 ),
        ("lsr", 0x0800, 0xf800, Instr.fmt_THUMB_1 ),
        ("asr", 0x1000, 0xf800, Instr.fmt_THUMB_1 ),
        ("add", 0x1800, 0xfe00, Instr.fmt_THUMB_2 ),
        ("add", 0x1c00, 0xfe00, Instr.fmt_THUMB_2_IMM ),
        ("sub", 0x1a00, 0xfe00, Instr.fmt_THUMB_2 ),
        ("sub", 0x1e00, 0xfe00, Instr.fmt_THUMB_2_IMM ),
        ("mov", 0x2000, 0xf800, Instr.fmt_THUMB_3 ),
        ("cmp", 0x2800, 0xf800, Instr.fmt_THUMB_3 ),
        ("add", 0x3000, 0xf800, Instr.fmt_THUMB_3 ),
        ("sub", 0x3800, 0xf800, Instr.fmt_THUMB_3 ),
        ("and", 0x4000, 0xffc0, Instr.fmt_THUMB_4 ),
        ("eor", 0x4040, 0xffc0, Instr.fmt_THUMB_4 ),
        ("lsl", 0x4080, 0xffc0, Instr.fmt_THUMB_4 ),
        ("lsr", 0x40c0, 0xffc0, Instr.fmt_THUMB_4 ),
        ("asr", 0x4100, 0xffc0, Instr.fmt_THUMB_4 ),
        ("adc", 0x4140, 0xffc0, Instr.fmt_THUMB_4 ),
        ("sbc", 0x4180, 0xffc0, Instr.fmt_THUMB_4 ),
        ("ror", 0x41c0, 0xffc0, Instr.fmt_THUMB_4 ),
        ("tst", 0x4200, 0xffc0, Instr.fmt_THUMB_4 ),
        ("neg", 0x4240, 0xffc0, Instr.fmt_THUMB_4 ),
        ("cmp", 0x4280, 0xffc0, Instr.fmt_THUMB_4 ),
        ("cmn", 0x42c0, 0xffc0, Instr.fmt_THUMB_4 ),
        ("orr", 0x4300, 0xffc0, Instr.fmt_THUMB_4 ),
        ("mul", 0x4340, 0xffc0, Instr.fmt_THUMB_4 ),
        ("bic", 0x4380, 0xffc0, Instr.fmt_THUMB_4 ),
        ("mvn", 0x43c0, 0xffc0, Instr.fmt_THUMB_4 ),
        ("add", 0x4400, 0xff00, Instr.fmt_THUMB_5 ),
        ("cmp", 0x4500, 0xff00, Instr.fmt_THUMB_5 ),
        ("mov", 0x4600, 0xff00, Instr.fmt_THUMB_5 ),
        ("bx", 0x4700, 0xff80, Instr.fmt_THUMB_5_BX, CF_STOP ),
        ("ldr", 0x4800, 0xf800, Instr.fmt_THUMB_6 ),
        ("str", 0x5000, 0xfe00, Instr.fmt_THUMB_7 ),
        ("strb", 0x5400, 0xfe00, Instr.fmt_THUMB_7 ),
        ("ldr", 0x5800, 0xfe00, Instr.fmt_THUMB_7 ),
        ("ldrb", 0x5c00, 0xfe00, Instr.fmt_THUMB_7 ),
        ("strh", 0x5200, 0xfe00, Instr.fmt_THUMB_8 ),
        ("ldsb", 0x5600, 0xfe00, Instr.fmt_THUMB_8 ),
        ("ldrh", 0x5a00, 0xfe00, Instr.fmt_THUMB_8 ),
        ("ldsh", 0x5e00, 0xfe00, Instr.fmt_THUMB_8 ),
        ("str", 0x6000, 0xf800, Instr.fmt_THUMB_9 ),
        ("ldr", 0x6800, 0xf800, Instr.fmt_THUMB_9 ),
        ("strb", 0x7000, 0xf800, Instr.fmt_THUMB_9_B ),
        ("ldrb", 0x7800, 0xf800, Instr.fmt_THUMB_9_B ),
        ("strh", 0x8000, 0xf800, Instr.fmt_THUMB_10 ),
        ("ldrh", 0x8800, 0xf800, Instr.fmt_THUMB_10 ),
        ("str", 0x9000, 0xf800, Instr.fmt_THUMB_11 ),
        ("ldr", 0x9800, 0xf800, Instr.fmt_THUMB_11 ),
        ("add", 0xa000, 0xf800, Instr.fmt_THUMB_12 ),
        ("add", 0xa800, 0xf800, Instr.fmt_THUMB_12_SP ),
        ("add", 0xb000, 0xff80, Instr.fmt_THUMB_13 ),
        ("sub", 0xb080, 0xff80, Instr.fmt_THUMB_13 ),
        ("push", 0xb400, 0xff00, Instr.fmt_THUMB_14 ),
        ("pop", 0xbc00, 0xff00, Instr.fmt_THUMB_14 ),
        ("push", 0xb500, 0xff00, Instr.fmt_THUMB_14_LR ),
        ("pop", 0xbd00, 0xff00, Instr.fmt_THUMB_14_PC, CF_STOP ),
        ("stmia", 0xc000, 0xf800, Instr.fmt_THUMB_15 ),
        ("ldmia", 0xc800, 0xf800, Instr.fmt_THUMB_15 ),
        ("beq", 0xd000, 0xff00, Instr.fmt_THUMB_16 ),
        ("bne", 0xd100, 0xff00, Instr.fmt_THUMB_16 ),
        ("bcs", 0xd200, 0xff00, Instr.fmt_THUMB_16 ),
        ("bcc", 0xd300, 0xff00, Instr.fmt_THUMB_16 ),
        ("bmi", 0xd400, 0xff00, Instr.fmt_THUMB_16 ),
        ("bpl", 0xd500, 0xff00, Instr.fmt_THUMB_16 ),
        ("bvs", 0xd600, 0xff00, Instr.fmt_THUMB_16 ),
        ("bvc", 0xd700, 0xff00, Instr.fmt_THUMB_16 ),
        ("bhi", 0xd800, 0xff00, Instr.fmt_THUMB_16 ),
        ("bls", 0xd900, 0xff00, Instr.fmt_THUMB_16 ),
        ("bge", 0xda00, 0xff00, Instr.fmt_THUMB_16 ),
        ("blt", 0xdb00, 0xff00, Instr.fmt_THUMB_16 ),
        ("bgt", 0xdc00, 0xff00, Instr.fmt_THUMB_16 ),
        ("ble", 0xdd00, 0xff00, Instr.fmt_THUMB_16 ),
        ("swi", 0xdf00, 0xff00, Instr.fmt_THUMB_17 ),
        ("b", 0xe000, 0xf800, Instr.fmt_THUMB_18, CF_STOP ),
        ("bl", 0xf800f000, 0xf800f800, Instr.fmt_THUMB_19, CF_CALL ),

        # Thumb2 extensions
        ("blx", 0x4780, 0xff80, (2, None) ),
        ("nop", 0xbf00, 0xffff, (2, None) ),
        ("it", 0xbf00, 0xff00, (2, None) ),
        ("uxtb", 0xb2c0, 0xffc0, (2, None) ),
        ("uxth", 0xb280, 0xffc0, (2, None) ),
        ("movs", 0x2000, 0xf800, (2, None) ),
        ("sub", 0x3800, 0xf800, (2, None) ),
        ("itt_eq", 0xbf04, 0xffff, (2, None) ),
        ("ite_eq", 0xbf0c, 0xffff, (2, None) ),
        ("uxtb_r4_r0", 0xb2c4, 0xffff, (2, None) ),
        ("cbz", 0xb100, 0xfd00, (2, None) ),
        ("cbnz", 0xb900, 0xfd00, (2, None) ),
        ("b.w", 0x8000f000, 0xd000f800, Instr.fmt_THUMB2_N1, CF_STOP  ),
        ("b.w", 0x9000f000, 0xd000f800, Instr.fmt_THUMB2_N2, CF_STOP),
        ("ldmia.w", 0x0000e890, 0x8000ffd0, Instr.fmt_THUMB2_RRL ),
        ("ldmia.w", 0x8000e890, 0x8000ffd0, Instr.fmt_THUMB2_RRL, CF_STOP ),
        ("stmdb", 0x0000e900, 0x0000ffd0, Instr.fmt_THUMB2_RRL ),
        ("ldrb.w", 0x0000f890, 0x0000fff0, Instr.fmt_THUMB2_RRI12 ),
        ("ldrb.w", 0x0000f810, 0x0fc0fff0, Instr.fmt_THUMB2_RRI12 ),
        ("add.w", 0x0000f100, 0x8000fbe0, Instr.fmt_THUMB2_RRI8 ),
        ("tbb", 0xf000e8d0, 0xfff0fff0, (4, None) ),
        ("mul.w", 0xf000fb00, 0xf0f0fff0, (4, None) ),
        ("stmia.w", 0x0000e880, 0x0000ffd0, (4, None) ),
        ("uxtb", 0xf080fa5f, 0xf080ffff, (4, None) ),
        ("strb.w", 0x0000f800, 0x0fc0fff0, (4, None) ),
        ("strb.w", 0x0000f880, 0x0000fff0, (4, None) ),
        ("strb", 0x0800f800, 0x0800fff0, (4, None) ),
        ("udiv", 0x00f0fbb0, 0x00f0fff0, (4, None) ),
        ("mls", 0x0010fb00, 0x00f0fff0, (4, None) ),
        ("eor.w", 0x0000ea80, 0x0000ffe0, (4, None) ),
        ("bic.w", 0x0000f020, 0x8000fbe0, (4, None) ),
        ("ands.w", 0x0000f000, 0x8000fbe0, (4, None) ),
        ("ldr.w", 0x0000f8d0, 0x0000fff0, (4, None) ),
        ("ldr", 0x0800f850, 0x0800fff0, (4, None) ),
        ("orr/mov.w", 0x0000ea40, 0x0000ffe0, (4, None) ),
        ("lsr.w", 0xf000fa20, 0xf0f0ffe0, (4, None) ),
        ("rsb", 0x0000ebc0, 0x0000ffe0, (4, None) ),
        ("add.w", 0x0000eb00, 0x0000ffe0, (4, None) ),
        ("strh", 0x0800f820, 0x0800fff0, (4, None) ),
        ("tst", 0x0f00f010, 0x8f00fbf0, (4, None) ),
        ("str", 0x0800f840, 0x0800fff0, (4, None) ),
        ("ldrb", 0x0800f810, 0x0800fff0, (4, None) ),
        ("ldrh.w", 0x0000f8bd, 0x0000ffff, (4, None) ),
        ("ldrh.w", 0x0000f8b0, 0x0000fff0, (4, None) ),
        ("ldrh.w", 0x0800f830, 0x0800fff0, (4, None) ),
        ("ldr.w", 0x0000f854, 0x0000ffff, (4, None) ),
        ("ldr.w", 0x0000f855, 0x0000ffff, (4, None) ),
        ("ldr.w_pc_sp", 0x0000f85d, 0x0000ffff, (4, None), CF_STOP ),
        ("strb.w", 0x0000f88d, 0x0000ffff, (4, None) ),
        ("str.w", 0x0000f8cd, 0x0000ffff, (4, None) ),
        ("strd", 0x0000e9cd, 0x0000ffff, (4, None) ),
        ("tst.w", 0x0000f013, 0x0000ffff, (4, None) ),
        ("tst.w", 0x0000f412, 0x0000ffff, (4, None) ),
        ("and.w", 0x0000f001, 0x0000ffff, (4, None) ),
        ("orr.w", 0x0000ea47, 0x0000ffff, (4, None) ),
        ("orr.w", 0x0000ea46, 0x0000ffff, (4, None) ),
        ("orr.w", 0x0000f441, 0x0000ffff, (4, None) ),
        ("orr.w", 0x0000f442, 0x0000ffff, (4, None) ),
        ("orr.w", 0x0000f443, 0x0000ffff, (4, None) ),
        ("orr.w", 0x0000f040, 0x0000ffff, (4, None) ),
        ("orr.w", 0x0000f041, 0x0000ffff, (4, None) ),
        ("orr.w", 0x0000f043, 0x0000ffff, (4, None) ),
        ("add.w", 0x0000f100, 0x0000ffff, (4, None) ),
        ("add.w", 0x0000f10d, 0x0000ffff, (4, None) ),
        ("movw", 0x0000f240, 0x0000ffff, (4, None) ),
        ("mov.w", 0x0000f44f, 0x0000ffff, (4, None) ),
        ("mov.w", 0x0000f04f, 0x0000ffff, (4, None) ),
        ("sub.w", 0x0000f5a0, 0x0000ffff, (4, None) ),
        ("sub.w", 0x0000f1a0, 0x8000fbe0, (4, None) ),
        ("sub.w", 0x0000f2a0, 0x8000fbe0, (4, None) ),
        ("subs.w", 0x0000f5b1, 0x0000ffff, (4, None) ),
        ("bic.w", 0x0000f021, 0x0000ffff, (4, None) ),
        ("bic.w", 0x0000f023, 0x0000ffff, (4, None) ),
        ("bic.w", 0x0000f423, 0x0000ffff, (4, None) ),
        ("bic.w", 0x0000f42c, 0x0000ffff, (4, None) ),
        ("str.w", 0x0000f8c2, 0x0000ffff, (4, None) ),
        ("str.w", 0x0000f8c3, 0x0000ffff, (4, None) ),
        ("str.w", 0x0000f8cc, 0x0000ffff, (4, None) ),
        ("msr", 0x0000f380, 0x0000ffff, (4, None) ),
    )

    def __init__(self):
        processor_t.__init__(self)
        self._init_instructions()
        self._init_registers()
    
    def _add_instruction(self, instr):
        self.instrs_list.append(instr)
    
    def _init_instructions(self):
        self.instrs_list = []
        self.short_insts = []
        self.long_insts = []

        for o in self.ops:
            instr = Instr(*o)
            self._add_instruction(instr)
            if instr.size == 2:
                self.short_insts.append(instr)
            else:
                self.long_insts.append(instr)

        self.instruc = [{ "name": i.name, "feature": i.flags } for i in self.instrs_list]
        self.instruc_end = len(self.instruc)

        self.instrs = {}
        for instr in self.instrs_list:
            self.instrs[instr.name] = instr
        
        self.instrs_ids = {}
        for i, instr in enumerate(self.instrs_list):
            self.instrs_ids[instr.name] = i
            instr.id = i

    def _init_registers(self):
        self.regNames = ["r%d" % d for d in range(16)]
        if SPECIAL_NAMES > 0:
            self.regNames[13] = "sp"
            self.regNames[14] = "lr"
            self.regNames[15] = "pc"
        self.reg_ids = {}
        for i, reg in enumerate(self.regNames):
            self.reg_ids[reg] = i
    
    def _pull_op_byte(self):
        ea = self.cmd.ea + self.cmd.size
        byte = get_full_byte(ea)
        self.cmd.size += 1
        return byte

    def _find_instr(self):
        op = self._pull_op_byte()
        op |= self._pull_op_byte() << 8
        
        for instr in self.short_insts:
            if instr.match(op):
                return instr, op

        op |= self._pull_op_byte() << 16
        op |= self._pull_op_byte() << 24

        for instr in self.long_insts:
            if instr.match(op):
                return instr, op

        return None, op

    def ana(self):
        instr, op = self._find_instr()
        #print('ana %08x %04x' % (self.cmd.ea, get_full_val(self.cmd.ea, 2)), instr)
        if not instr:
            #fail
            return 0

        self.cmd.itype = instr.id

        operands = [self.cmd[i] for i in range(6)]
        for o in operands:
            o.type = o_void
        instr.parseOperands(operands, op, self.cmd)

        return self.cmd.size

    def emu(self):
        features = self.cmd.get_canon_feature()
        #print('emu', features)
        for i in range(6):
            op = self.cmd[i]
            if op.type == o_void:
                break
            elif op.type == o_near:
                if features & CF_CALL:
                    fl = fl_CN
                else:
                    fl = fl_JN
                ua_add_cref(0, op.addr, fl)

        if features & CF_JUMP:
            QueueMark(Q_jumps, self.cmd.ea)
        if not (features & CF_STOP):
            if features & CF_CALL:
                ua_add_cref(0, self.cmd.ea + self.cmd.size, fl_RET_FROM_CALL)
            else:
                ua_add_cref(0, self.cmd.ea + self.cmd.size, fl_F)
        return True
    
    def outop(self, op):
        if op.type == o_reg:
            out_register(self.regPrefix + self.regNames[op.reg])
        elif op.type == o_imm:
            instr = self.instrs_list[self.cmd.itype]
            if True: #instr.name in ("add",):
                # bit numbers/shifts are always decimal
                OutChar('#')
                OutLong(op.value, 10)
            else:
                OutValue(op, OOFW_IMM)
        elif op.type == o_near:
            ok = out_name_expr(op, op.addr, BADADDR)
            if not ok:
                out_tagon(COLOR_ERROR)
                OutLong(op.addr, 16)
                out_tagoff(COLOR_ERROR)
                QueueMark(Q_noName, self.cmd.ea)
        elif op.type == o_displ:
            out_register(self.regPrefix + self.regNames[op.phrase])
            OutLine(", ")
            OutValue(op, OOF_ADDR)
        else:
            return False
        return True

    def out(self):
        buf = init_output_buffer(1024)
        OutMnem()

        instr = self.instrs_list[self.cmd.itype]

        inreglist = False
        for i in range(6):
            if self.cmd[i].type == o_void:
                break

            if self.cmd[i].flags & OF_SHOW == 0:
                continue
            if i > 0:
                out_symbol(',')
            OutChar(' ')

            if instr.name in ('str', 'strb', 'ldr', 'ldrb', 'strh', 'ldrh',
                              'ldsb', 'ldsh', 'str.w', 'strb.w', 'ldr.w',
                              'ldrb.w', 'strh.w', 'ldrh.w', 'ldsb.w',
                              'ldsh.w') and i == 1:
                OutChar('[')

            if instr.name in ('ldmia') and i == 1:
                OutChar('{')

            if self.cmd[i].type == o_reglist:
                OutChar('{')
                k = False
                for j in range(16):
                    if self.cmd[i].reglist & 1 << j:
                        if k:
                            out_symbol(',')
                            OutChar(' ')
                        k = True
                        out_register(self.regPrefix + self.regNames[j])
                if self.cmd[i + 1].type == o_reg and \
                    self.cmd[i + 1].reg in (REG_LR, REG_PC):
                   inreglist = True
                else:
                    OutChar('}')
                continue

            out_one_operand(i)

            if instr.name in ('ldmia', 'ldmia.w') and i == 0:
                OutChar('!')

            if instr.name in ('str', 'strb', 'ldr', 'ldrb', 'strh', 'ldrh',
                              'ldsb', 'ldsh', 'str.w', 'strb.w', 'ldr.w',
                              'ldrb.w', 'strh.w', 'ldrh.w', 'ldsb.w',
                              'ldsh.w') and i == 2:
                OutChar(']')

            if inreglist:
                OutChar('}')

        term_output_buffer()
        cvar.gl_comm = 1
        MakeLine(buf)


def PROCESSOR_ENTRY():
    return ArmProcessor()
