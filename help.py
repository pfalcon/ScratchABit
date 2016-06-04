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
Global commands ("letter" commands are case-sensitive, e.g. Shift+a
is actually "capital A", so make sure Caps Lock is right):

g - Goto address
Esc - Return to address from previous Enter cmd (as stack)
Shift+s - Save database
q - Quit

Shift+i - Show memory map (see key below)
Shift+w - Write complete disassembly listing to file 'out.lst'
Ctrl+q - Show problems list

Current address commands:

u - Undefine
c - Make code
d - Make/Cycle data
a - Make ASCII string
n - (Re)name address (make label)
i - Info
Ctrl+w - Write current function to a file
/ - Search thru listing starting from current addr
Shift+/ - Continue search

Current selected argument commands (require cursor to be on this
argument, but if an instruction has only one argument, will work
with cursor anywhere in the line):

Enter - Goto address in operand
h - Decimal/hex number
o - Make an offset/address

Key to cross-reference types as appears in the listing
("xref: <addr> <type>"):
c - call from <addr>
j - jump from <addr>
r - read at <addr>
w - write at <addr>
o - offset/address taken at <addr>

Key to memory map (Shift+i):
For each byte, type is shown:
. - unknown
F - first byte of instruction, the instruction belonging
    to a known function
f - continuation byte of function's instruction
C - first byte of instruction, not belonging to a function.
c - continuation byte of non-function instruction
D - first byte of a data item
d - continuation byte of a data item
X - conflicting flags (e.g. both code and data)
"""

from picotui.editorext import Viewer

L = 5
T = 2
W = 70
H = 20

cpu_help = ""

def set_cpu_help(txt):
    global cpu_help
    cpu_help = "\nCPU-specific information:\n" + txt


def help(screen):
    screen.dialog_box(L, T, W, H)
    v = Viewer(L + 1, T + 1, W - 2, H - 2)
    v.set_lines((HELP + cpu_help).splitlines())
    v.loop()
