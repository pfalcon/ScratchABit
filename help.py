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
Global commands (for letter commands, case matters):

g - Goto address
Esc - Return to address from previous Enter cmd (as stack)
S - Save database
Ctrl+q - Show problems list
q - Quit

Current address commands:

u - Undefine
c - Make code
d - Make/Cycle data
a - Make ASCII string
n - (Re)name address (make label)
i - Info

Current selected argument commands (ok to work on current command
if only 1 suitable arg):

Enter - Goto address in operand
h - Decimal/hex number (TODO)
o - Make an offset/address

Cross-reference type key (xref: <addr> <type>):
c - call from <addr>
j - jump from <addr>
r - read at <addr>
w - write at <addr>
o - offset/address taken at <addr>
"""

from pyedit.editorext import Viewer

L = 5
T = 2
W = 70
H = 20

def help(screen):
    screen.dialog_box(L, T, W, H)
    v = Viewer(L + 1, T + 1, W - 2, H - 2)
    v.set_lines(HELP.splitlines())
    v.loop()
