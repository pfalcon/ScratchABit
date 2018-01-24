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
import capstone
import _any_capstone


arch_id = "arm_32"

dis_arm = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
dis_thumb = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)

def PROCESSOR_ENTRY():
    return _any_capstone.Processor(dis_arm, dis_thumb)
