ScratchABit CPU plugin directory
================================

This directory holds IDAPython-compatible CPU plugins and their supporting
modules and files.

ScratchABit is shipped with few default plugins described below. The naming
convention followed by default plugins is:

    <arch>_<bitness>[_<subarch>]_<engine>.py

Where `<arch>` is an architecture idenifier, `<bitness>` is number of native
bits in a word, `<subarch>` is an optional subarchitecture/variant, `<engine>`
is an underlying library/project used for disassembly. Some plugins may deviate
from this naming convention. File starting with underscore (`_`) and
subdirectories of this directory are not plugins per se, but are supporting
modules for the plugins.

Currently available general-purpose default plugins are:

* `arm_32_capstone` - ARM 32-bit, using Capstone disassembly engine
  (must be installed separately, as described in the top-level README).
  This plugin handles all the following instruction modes: ARM (32-bit
  instructions), Thumb (16-bit instructions), Thumb2 (16-bit and 32-bit
  instructions, extension of Thumb mode). Whether a function is
  disassembled in ARM or Thumb mode depends on the standard rules for
  the architecture: if function address is even, it's ARM, if odd -
  it's Thumb. (This applies to all addresses, starting from an
  entrypoint(s) - if you want particular addresses to be disassembled
  in Thumb mode, specify them with the lowest bit set to 1 in the
  `[entrypoints]` section of your `.def` file).
* `x86_16_capstone`, `x86_32_capstone`, `x86_64_capstone` - Intel x86,
  16-bit, 32-bit, and 64-bit modes, using Capstone disassembly engine.
* `x86_16_pymsasid`, `x86_32_pymsasid`, `x86_64_pymsasid` - Intel x86,
  16-bit, 32-bit, and 64-bit modes, using pure-Python Pymsasid3
  disassembly library. Unlike Capstone, which needs to be installed
  separately (and may require a C compiler), Pymsasid3 is included as
  a git submodule in the ScratchABit repository, and is available by
  default if it is cloned following the instructions in the top-level
  README.

Special-purposes plugins are listed below. As name suggests, they exist
for specific needs. Don't use them unless you are sure that you need them.
(A typical case for using them would be if there are problems with the
general-purpose plugins above, e.g. to compare disassembly results.)

* `arm_thumb` - A simple pure-Python plugin for ARM Thumb. It doesn't work
  with ARM native (32-bit) instructions or Thumb2.
* `arm_32_arm_capstone` - A Capstone-based ARM plugin which disassembles
  all instructions only as 32-bit ARM instructions (even if normally some
  of them would be disassembled as Thumb instructions). Normally, you
  should use `arm_32_capstone` instead.
* `arm_32_thumb_capstone` - Like above, but forces disassembly of all
  instructions in Thumb/Thumb2 mode. Likewise, normally `arm_32_capstone`
  should be used instead.
