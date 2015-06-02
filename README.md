ScratchABit
===========

ScratchABit is an interactive incremental disassembler with data/control
flow analysis capabilities. ScratchABit is dedicated to the efforts of
the OpenSource reverse engineering community (reverse engineering to
produce OpenSource drivers/firmware for hardware not properly supported
by vendors).

ScratchABit supports well-known in the community IDAPython API to write
disassembly/extension modules.

ScratchABit is a work in progress, features are added on as needed basis,
contributions are welcome.

ScratchABit is released under the terms of GNU General Public License v3
(GPLv3).


Requirements/manifesto
----------------------

1. Should not be written in an obfuscated language. These includes languages
which are too low-level, which allow to access non-initialized variables,
which don't differentiate between variables and functions/procedures, which
start array indexes from arbitrary numbers, etc., etc. ScratchABit is
written in Python (modern version, Python3) for your pleasure and sanity.

2. User interface framework should allow user interaction of the needed
level, not add dependencies, bloat, issues, and incompatibilities between
framework's versions. ScratchABit currently uses simple (no color even)
full-screen text user interface, using ANSI/VT100 terminal escape sequences
(yes, even curses library was deemed too bloat a dependency to force upon
users).

3. Should leverage easy to use text formats to store "database", to
facilitate easy reuse and tool writing, and storage in version control
systems.


Quick start
-----------

To use ScratchABit, you need Python3 installed and VT100 (minimum) or
XTerm (recommended) terminal or terminal emulator (any Unix system
should be compliant, like Linux/BSD/etc, see also FAQ).

Clone the code using "git clone --recursive". If you cloned code without
"--recursive", run "git submodule update --init".

If you want to disassemble a file in self-describing executabel format
(like ELF), just pass it as an argument to scratchabit.py. The repository
includes `example-elf` (x86 32bit) for quick start:

    python3 scratchabit.py example-elf

Alternatively, if you want to disassemble a raw binary file, you need
to creat a .def (definition) file, to specify what memory areas are
defined for the code, where to load binary file, etc. The repository
includes a simple x86_64 raw binary code, and corresponding .def file:

    python3 scratchabit.py example.def

Press F1 if in doubt what to do next.


TODO/Things to decide
---------------------

* Parse and use debugging information present in ELF (etc.) files.
* Currently uses multiple files for "database", each storing particular
  type of information. Switch to a single YAML file instead?
* Add color (low priority, (unbloated!) patches welcome).
* Few important UI commands to implement yet for comfortable work (e.g.
  list/search a label).
* Offer to save DB on quit if modified.
* Git integration for DB saving.
* Improve robustness (add exception handler at the main loop level, don't
  abort the application, show to user/log and continue).
* Try to deal with code flow inconsistencies (e.g. within an instruction
  - low priority for intended usage) and data access inconsistencies (e.g.
  accessing individual bytes of previosly detected word - higher priority).
* See how to support other types of IDAPython plugins besides just processor
  modules.


FAQ
---

> Q: What processors/architectures are supported?

A: ScratchABit doesn't support any processor architectures on its own,
it is fully retargettable using IDAPython API plugins. Many plugins are
available, writing a new plugin is easy. To let users test-drive
ScratchABit, a very simple (!) X86 processor plugin is included in the
distribution, using Pymsasid disassembler under the hood.

> Q: I'm not on Linux, how can I run ScratchABit?

A: Install Linux in an emulator on your system and rejoice.

> Q: Mandatory screenshot?

A: Sure:
![screenshot](https://raw.githubusercontent.com/pfalcon/ScratchABit/master/docs/scratchabit.png)
