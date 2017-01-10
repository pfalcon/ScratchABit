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
should be compliant, like Linux/BSD/etc., see FAQ below for more).

Clone the code using:

    git clone --recursive https://github.com/pfalcon/ScratchABit

If you cloned code without `--recursive`, run `git submodule update --init`.

If you want to disassemble a file in self-describing executable format
(like ELF), just pass it as an argument to `ScratchABit.py`. The repository
includes `example-elf` (x86 32bit) for quick start:

    python3 ScratchABit.py example-elf

Alternatively, if you want to disassemble a raw binary file, you need
to create a .def (definition) file, to specify what memory areas are
defined for the code, at which address to load binary file, etc. (Note:
a .def file may be useful for .elf and similar files too.) The repository
includes a simple x86_64 raw binary code, and the corresponding .def file:

    python3 ScratchABit.py example.def

Press F1 if in doubt what to do next (ScratchABit works similarly to other
interactive dissamblers; some previous experience or background reading may
be helpful). Press F9 to access menus (mouse works too in XTerm-compatible
terminals).

Using Plugins
-------------

IDAPython processor plugins can be loaded from anywhere on the Python
module path. Alternatively, you can symlink the plugin `.py` file into
the `plugins/cpu/` subdirectory.

After the plugin is made available, create a new definition file based
on `example.def` that sets the plugin module name in the `cpu xxx` line.

For a very simple example that uses an external plugin, see this
[esp8266.def file](https://gist.github.com/projectgus/f898d5798e3e44240796)
that works with the xtensa.py plugin from the
[ida-xtensa2 repository](https://github.com/pfalcon/ida-xtensa2).

TODO/Things to decide
---------------------

* ~~Currently uses multiple files for "database", each storing particular
  type of information. Switch to a single YAML file instead?~~
* Add color (low priority, (unbloated!) patches welcome).
* ~~Few important UI commands to implement yet for comfortable work.~~ (
  All the most important commands should be there, other functionality is
  expected to be implemented using plugins).
* Offer to save DB on quit if modified.
* Git integration for DB saving.
* ~~Improve robustness (add exception handler at the main loop level, don't
  abort the application, show to user/log and continue).~~
* Try to deal with code flow inconsistencies (e.g. within an instruction
  - low priority for intended usage) and data access inconsistencies (e.g.
  accessing individual bytes of previosly detected word - higher priority).
  (Improved in 1.4.)
* See how to support other types of IDAPython plugins besides just processor
  modules.
* Parse and use debugging information (e.g. DWARF) present in ELF (etc.)
  files.


FAQ
---

> Q: What processors/architectures are supported?

A: ScratchABit doesn't support any processor architectures on its own,
it is fully retargettable using IDAPython API plugins. Many plugins are
available, writing a new plugin is easy. To let users test-drive
ScratchABit, a very simple (!) X86 processor plugin is included in the
distribution, using Pymsasid disassembler under the hood.

> Q: I'm not on Linux, how can I run ScratchABit?

A: Install Linux in an emulator/VM on your system and rejoice.

> Q: Mandatory screenshot?

A: Sure:

![screenshot](https://raw.githubusercontent.com/pfalcon/ScratchABit/master/docs/scratchabit.png)
