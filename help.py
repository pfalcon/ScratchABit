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
HELP = """\
Global commands:

g - Goto address

Current address commands:

u - Undefine
c - Make code
d - Make/Cycle data
a - Make ASCII string

Current argument commands (work on current command
if only 1 suitable arg):

h - Decimal/hex number
o - Offset
"""

from editor_api import Viewer

L = 5
T = 2
W = 70
H = 20

def help(screen):
    screen.dialog_box(L, T, W, H)
    v = Viewer(L + 1, T + 1, W - 2, H - 2)
    v.set_lines(HELP.splitlines())
    v.loop()
