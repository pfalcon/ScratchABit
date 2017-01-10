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
from scratchabit import engine
import idaapi


SEGATTR_PERM = 1


def GetSegmentAttr(ea, attr):
    assert attr == SEGATTR_PERM
    off, area = engine.ADDRESS_SPACE.addr2area(addr)
    props = engine.area_props(area)
    ret = 0
    if "R" in props:
        ret |= idaapi.SEGPERM_READ
    if "W" in props:
        ret |= idaapi.SEGPERM_WRITE
    if "X" in props:
        ret |= idaapi.SEGPERM_EXEC


# Make filler
def MakeAlign(ea, cnt, align):
    engine.ADDRESS_SPACE.make_filler(ea, cnt)
