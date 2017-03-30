import logging as log
import struct

from pyelftools.elftools.elf.elffile import ELFFile
from pyelftools.elftools.elf.relocation import Relocation
from pyelftools.elftools.elf.enums import ENUM_D_TAG
from pyelftools.elftools.elf.constants import SH_FLAGS, P_FLAGS
from pyelftools.elftools.elf.sections import SymbolTableSection
from pyelftools.elftools.elf.relocation import RelocationSection
from pyelftools.elftools.common.exceptions import ELFError

import idaapi


# Whether to add comments of relocs pointing to addresses.
# Useful for debugging loader, but mostly a noise afterwards.
RELOC_COMMENTS = False

MACH_MAP = {
    "EM_386": "x86",
    "EM_X86_64": "x86",
    "EM_XTENSA": "xtensa",
    "EM_ARM": "arm",
}

RELOC_TYPES = {}

RELOC_TYPES["EM_XTENSA"] = {
    0: "R_XTENSA_NONE",
    1: "R_XTENSA_32",
    11: "R_XTENSA_ASM_EXPAND",
    19: "R_XTENSA_DIFF32",
    20: "R_XTENSA_SLOT0_OP",
}

XTENSA_PROP_LITERAL            = 0x00000001
XTENSA_PROP_INSN               = 0x00000002
XTENSA_PROP_DATA               = 0x00000004
XTENSA_PROP_UNREACHABLE        = 0x00000008


def detect(fname):
    f = open(fname, "rb")
    try:
        elffile = ELFFile(f)
    except ELFError:
        return None

    #print(elffile.header)
    #print(elffile["e_ident"]["EI_CLASS"])
    bitness = 32 if elffile["e_ident"]["EI_CLASS"] == "ELFCLASS32" else 64
    return "%s_%s" % (MACH_MAP[elffile["e_machine"]], bitness)


# PLT is Procedure Linkage Table, part of (read-only) code
# GOT is Global Offset Table, part of (generally read-write) data
# GOT is split in 2 parts: normal GOT, used by application,
# and PLTGOT, referenced by code in PLT.

def adjust_plt_addr(addr):
    """Given address pointing inside PLT entry (usually to 'lazy load'
    handler), return pointer to the beginning of PLT.
    """
    # TODO: Implementation is arch-dependent
    # Ref: eresi/libelfsh/plt.c

    # x86_32
    return addr & ~0xf

def p_flags_to_access(x):
    s = ''
    for flag, c in ((P_FLAGS.PF_R, "R"), (P_FLAGS.PF_W, "W"), (P_FLAGS.PF_X, "X")):
        if x & flag:
             s += c
    return s

def sh_flags_to_access(x):
    s = "R"
    for flag, c in ((SH_FLAGS.SHF_WRITE, "W"), (SH_FLAGS.SHF_EXECINSTR, "X")):
        if x & flag:
             s += c
    return s


def load_segments(aspace, elffile):
    log.debug("Loading ELF segments")

    wordsz = elffile.elfclass // 8

    for seg in elffile.iter_segments():
        #print(seg)
        #print(seg.header)
        #print("p_vaddr=%x p_memsz=%x" % (seg["p_vaddr"], seg["p_memsz"]))
        #print()
        if seg["p_type"] == "PT_LOAD":
            if seg["p_memsz"]:
                access = p_flags_to_access(seg["p_flags"])
                aspace.add_area(seg["p_vaddr"], seg["p_vaddr"] + seg["p_memsz"] - 1, {"access": access})
                seg.stream.seek(seg['p_offset'])
                aspace.load_content(seg.stream, seg["p_vaddr"], seg["p_filesz"])
            else:
                log.warning("Skipping empty ELF segment: %s", seg.header)
        elif seg["p_type"] == "PT_DYNAMIC":
            aspace.set_label(seg["p_vaddr"], "ELF.DYNAMIC")

            symtab = {}
            for i, s in enumerate(seg.iter_symbols()):
                #print(s.name, hex(s["st_value"]), s.entry)
                symtab[i] = s
                if s["st_shndx"] != "SHN_UNDEF":
                    aspace.make_unique_label(s["st_value"], str(s.name, "utf-8"))

                    if s["st_info"]["type"] == "STT_FUNC":
                        aspace.analisys_stack_push(s["st_value"], idaapi.fl_CALL)
                    if s["st_info"]["type"] == "STT_OBJECT":
                        # TODO: Set as data of given s["st_size"]
                        pass

            rel = relsz = relent = None
            pltrel = pltrelsz = pltenttype = None

            for tag in seg.iter_tags():
                d_ptr = tag["d_ptr"]
                #print(tag, hex(d_ptr))
                if tag['d_tag'] == 'DT_PLTGOT':
                    aspace.set_label(d_ptr, "ELF.PLTGOT")
                    aspace.make_data(d_ptr, wordsz)
                    aspace.make_arg_offset(d_ptr, 0, aspace.get_data(d_ptr, wordsz))

                    aspace.set_label(d_ptr + wordsz, "ELF.CUR_OBJ")
                    aspace.make_data(d_ptr + wordsz, wordsz)
                    aspace.append_comment(d_ptr + wordsz, "Identifier of this ELF object")

                    aspace.set_label(d_ptr + wordsz * 2, "ELF.SYM_LOOKUP")
                    aspace.make_data(d_ptr + wordsz * 2, wordsz)
                    aspace.append_comment(d_ptr + wordsz * 2, "Dynamic linker routine for symbol lookup")

                elif tag['d_tag'] == 'DT_JMPREL':
                    aspace.set_label(d_ptr, "ELF.JMPREL")
                    pltrel = d_ptr
                elif tag['d_tag'] == 'DT_PLTRELSZ':
                    pltrelsz = d_ptr
                elif tag['d_tag'] == 'DT_PLTREL':
                    pltenttype = d_ptr

                elif tag['d_tag'] == 'DT_REL':
                    rel = d_ptr
                    aspace.set_label(d_ptr, "ELF.REL")
                elif tag['d_tag'] == 'DT_RELSZ':
                    relsz = d_ptr
                elif tag['d_tag'] == 'DT_RELENT':
                    relent = d_ptr

                elif tag['d_tag'] == 'DT_RELA':
                    aspace.set_label(d_ptr, "ELF.RELA")

                elif tag['d_tag'] == 'DT_INIT_ARRAY':
                    aspace.set_label(d_ptr, "ELF.INIT_ARRAY")
                elif tag['d_tag'] == 'DT_FINI_ARRAY':
                    aspace.set_label(d_ptr, "ELF.FINI_ARRAY")
                elif tag['d_tag'] == 'DT_INIT':
                    aspace.set_label(d_ptr, "ELF.INIT")
                    aspace.analisys_stack_push(d_ptr)
                elif tag['d_tag'] == 'DT_FINI':
                    aspace.set_label(d_ptr, "ELF.FINI")
                    aspace.analisys_stack_push(d_ptr)

            if rel is not None:
                aspace.make_data_array(rel, wordsz, relsz // wordsz)

            if pltrel is not None:
                aspace.make_data_array(pltrel, wordsz, pltrelsz // wordsz)

                if pltenttype == ENUM_D_TAG["DT_RELA"]:
                    entry_struct = elffile.structs.Elf_Rela
                else:
                    entry_struct = elffile.structs.Elf_Rel

                end = pltrel + pltrelsz
                while pltrel < end:
                    data = aspace.get_bytes(pltrel, entry_struct.sizeof())
                    entry = entry_struct.parse(data)
                    reloc = Relocation(entry, elffile)
                    sym = symtab[reloc['r_info_sym']]
                    #print(reloc, sym.name, sym.entry)
                    symname = str(sym.name, "utf-8")
                    aspace.append_comment(pltrel, symname + ".plt")
                    aspace.make_arg_offset(pltrel, 0, aspace.get_data(pltrel, wordsz))

                    got_addr = reloc["r_offset"]
                    aspace.set_label(got_addr, symname + ".got")
                    aspace.make_data(got_addr, wordsz)
                    lazy_code = aspace.get_data(got_addr, wordsz)
                    aspace.make_arg_offset(got_addr, 0, lazy_code)

                    aspace.set_label(lazy_code, symname + ".lazy")
                    aspace.analisys_stack_push(lazy_code)

                    real_func = adjust_plt_addr(lazy_code)
                    aspace.make_unique_label(real_func, symname)
                    aspace.analisys_stack_push(real_func)

                    pltrel += entry_struct.sizeof()

    return elffile["e_entry"]


def load_sections(aspace, elffile):
    log.info("Processing ELF sections")
    wordsz = elffile.elfclass // 8
    is_exe = elffile["e_type"] == "ET_EXEC"
    # Use pretty weird address to help distinuish addresses from literal numbers
    addr_cnt = 0x55ab0000
    sec_map = {}

    # As section order may be arbitrary, make sure to allocate allocatable sections first
    log.info("Allocating and loading ELF sections")
    for i, sec in enumerate(elffile.iter_sections()):
        if sec["sh_flags"] & SH_FLAGS.SHF_ALLOC and sec["sh_size"]:
            name = str(sec.name, "ascii")
            size = sec["sh_size"]
            if is_exe:
                addr = sec["sh_addr"]
            else:
                addr = addr_cnt
            #print(name, sec.header)
            access = sh_flags_to_access(sec["sh_flags"])
            aspace.add_area(addr, addr + size - 1, {"name": name, "access": access})
            if sec["sh_type"] == "SHT_PROGBITS":
                sec.stream.seek(sec['sh_offset'])
                aspace.load_content(sec.stream, addr, size)
            aspace.make_unique_label(addr, name)
            sec_map[i] = (sec, addr)
            addr_cnt += size + 0xfff
            addr_cnt &= ~0xfff
            #print()

    # Process symbols
    for _sec in elffile.iter_sections():
        if not isinstance(_sec, SymbolTableSection):
            continue

        sec_name = str(sec.name, "ascii")

        log.info("Processing symbols from section '%s'" % sec_name)
        symtab = {}
        for i, sym in enumerate(_sec.iter_symbols()):
            symtab[i] = sym
#            print(sym.name, sym.entry)

            if sym.name and sym["st_shndx"] != "SHN_UNDEF" \
                        and sym["st_info"]["type"] in ("STT_NOTYPE", "STT_FUNC", "STT_OBJECT", "STT_COMMON"):
                sec_start = 0
                if not is_exe and sym["st_shndx"] != "SHN_ABS":
                    sec, sec_start = sec_map[sym["st_shndx"]]

                symname = str(sym.name, "utf-8")
                aspace.make_unique_label(sym["st_value"] + sec_start, symname)

                if sym["st_info"]["type"] == "STT_FUNC":
                    aspace.analisys_stack_push(sym["st_value"] + sec_start, idaapi.fl_CALL)
                    if sym["st_size"]:
                        aspace.make_func(sym["st_value"] + sec_start, sym["st_value"] + sec_start + sym["st_size"])
                    else:
                        aspace.make_func(sym["st_value"] + sec_start, None)
                if sym["st_info"]["type"] == "STT_OBJECT":
                    aspace.make_data_array(sym["st_value"] + sec_start, 1, sym["st_size"])


    # Process relocations - using relocations allows to tag various data types

    reloc_types = RELOC_TYPES.get(elffile["e_machine"], {})

    for rel_sec in elffile.iter_sections():
        if not isinstance(rel_sec, RelocationSection):
            continue

        sec_name = str(rel_sec.name, "ascii")
        log.info("Processing relocations from section '%s'" % sec_name)
        if rel_sec["sh_info"] not in sec_map:
            continue

        # If it's linked executable, then reloc's r_offset fields are already
        # absolute (i.e. have section start added).
        if is_exe:
            target_sec_addr = 0
        else:
            target_sec, target_sec_addr = sec_map[rel_sec["sh_info"]]

        #print(rel_sec.header, target_sec.name)
        for reloc in rel_sec.iter_relocations():
            #print(reloc)

            sym = symtab[reloc['r_info_sym']]
            symname = str(sym.name, "utf-8")
            if reloc.is_RELA() and reloc["r_addend"] != 0:
                symname += "+0x%x" % reloc["r_addend"]

            value = None
            sym_sec, sym_sec_addr = None, None
            if sym.entry["st_shndx"] != "SHN_UNDEF":
                value = sym.entry["st_value"]
                if reloc.is_RELA():
                    value += reloc["r_addend"]
                if sym.entry["st_shndx"] != "SHN_ABS":
                    if not is_exe:
                        sym_sec, sym_sec_addr = sec_map[sym.entry["st_shndx"]]
                        value += sym_sec_addr


            raddr = target_sec_addr + reloc["r_offset"]
            rel_type = reloc_types.get(reloc["r_info_type"], "reltype%d" % reloc["r_info_type"])

            if RELOC_COMMENTS:
                aspace.append_comment(raddr, "%s: %s" % (rel_type, symname))

            if rel_type == "R_XTENSA_32":
                aspace.make_data(raddr, wordsz)
                #print(sym.entry)
                if value is not None:
                    data = aspace.get_data(raddr, wordsz)
                    if is_exe:
                        if data != value:
                            log.debug("Computed reloc value and value present in fully linked file differ: 0x%x vs 0x%x", value, data)
                    else:
                        data += value
                        aspace.set_data(raddr, data, wordsz)
                    aspace.make_arg_offset(raddr, 0, data)
                else:
                    # Undefined symbol
                    # TODO: This is more or less hacky way to do this. It would be
                    # better to explicitly assign a symbolic alias to a value at
                    # particular address, but so far we assume call below to do
                    # that.
                    aspace.make_arg_offset(raddr, 0, symname)
            elif rel_type == "R_XTENSA_SLOT0_OP":
                if is_exe:
                    continue
                opcode = aspace.get_byte(raddr)
                if opcode & 0xf == 0x5:
                    # call
                    if value is not None:
                        p = raddr
                        value -= ((p & ~0x3) + 4)
                        assert value & 0x3 == 0
                        value = value >> 2
                        aspace.set_byte(p, (opcode & ~0xc0) | ((value << 6) & 0xc0))
                        aspace.set_byte(p + 1, value >> 2)
                        aspace.set_byte(p + 2, value >> 10)
                if opcode & 0xf == 0x1:
                    # l32r
                    pass
#        break

    def load_xt_prop(elffile, symtab):
        sec = elffile.get_section_by_name(b".xt.prop")
        if not sec:
            return
        print("Loading Xtensa properties from section:", sec.name.decode("utf-8"))
        sec.stream.seek(sec['sh_offset'])
        prop_arr = [0] * (sec["sh_size"] // 4)
        for i in range(len(prop_arr)):
            val = sec.stream.read(4)
            prop_arr[i] = struct.unpack("<I", val)[0]
        #print(prop_arr)

        rel_sec = elffile.get_section_by_name(b".rela.xt.prop")
        print("Loading Xtensa properties from section:", rel_sec.name.decode("utf-8"))
        for reloc in rel_sec.iter_relocations():
            sym = symtab[reloc['r_info_sym']]
            symname = str(sym.name, "utf-8")
            #print(reloc, symname)
            value = sym.entry["st_value"] + reloc["r_addend"]
            if sym.entry["st_shndx"] != "SHN_ABS":
                if not is_exe:
                    sym_sec, sym_sec_addr = sec_map[sym.entry["st_shndx"]]
                    value += sym_sec_addr
            #print(hex(value))
            if not is_exe:
                prop_arr[reloc["r_offset"] // 4] += value

        # Process entries in reverse order, as they will be pushed to stack,
        # so will be processed reversed again.
        for i in range(len(prop_arr) - 3, -1, -3):
            start, size, flags = prop_arr[i:i+3]
            #print("Xtensa prop entry: %08x(%x) %x" % (start, size, flags))
            if flags & XTENSA_PROP_INSN:
                aspace.analisys_stack_push(start)
            if flags & XTENSA_PROP_DATA:
                c = aspace.get_comment(start) or ""
                if size != 0 or "XTENSA_PROP_DATA" not in c:
                    if RELOC_COMMENTS:
                        aspace.append_comment(start, "XTENSA_PROP_DATA (%d)" % size)
                    # Don't trust XTENSA_PROP_DATA with size=0
                    # For linked exe, there were cases when such
                    # pointed straight into the code and broke all
                    # the fun.
                    #if not size:
                    #    size = 1
                    if size:
                        aspace.make_data_array(start, 1, size, prefix="xtensa: ")
            if flags & XTENSA_PROP_LITERAL:
                while size:
                    aspace.make_data(start, wordsz)
                    start += 4
                    size -= 4

    load_xt_prop(elffile, symtab)

    if is_exe:
        return elffile["e_entry"]


def load(aspace, fname):

    f = open(fname, "rb")
    elffile = ELFFile(f)
    #print(elffile)
    #print(elffile.header)
    #print("entry: %x" % elffile["e_entry"])
    #print()

    if elffile.num_sections():
        return load_sections(aspace, elffile)

    if elffile.num_segments():
        return load_segments(aspace, elffile)

    assert False, "No ELF sections or segments found"


if __name__ == "__main__":
    import sys
    log.basicConfig(level=log.DEBUG, stream=sys.stdout)
    class Stub:
        def __getattr__(self, attr):
            def dump(*args, **kw):
                args = [hex(a) if isinstance(a, int) else repr(a) for a in args]
                args = ", ".join(args)
                print("AS.%s(%s, %s)" % (attr, args, kw))
                return 0
            return dump

    load(Stub(), sys.argv[1])
