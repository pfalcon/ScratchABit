import logging as log

from pyelftools.elftools.elf.elffile import ELFFile
from pyelftools.elftools.elf.relocation import Relocation
from pyelftools.elftools.elf.enums import ENUM_D_TAG
from pyelftools.elftools.elf.constants import SH_FLAGS, P_FLAGS
from pyelftools.elftools.elf.sections import SymbolTableSection
from pyelftools.elftools.elf.relocation import RelocationSection

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
                    aspace.set_label(s["st_value"], str(s.name, "utf-8"))

                    if s["st_info"]["type"] == "STT_FUNC":
                        aspace.analisys_stack_push(s["st_value"])
                    if s["st_info"]["type"] == "STT_OBJECT":
                        # TODO: Set as data of given s["st_size"]
                        pass

            rel = relsz = relent = None
            pltrel = pltrelsz = pltenttype = None

            for tag in seg.iter_tags():
                d_ptr = tag["d_ptr"]
                print(tag, hex(d_ptr))
                if tag['d_tag'] == 'DT_PLTGOT':
                    aspace.set_label(d_ptr, "ELF.PLTGOT")
                    aspace.make_data(d_ptr, wordsz)
                    aspace.make_arg_offset(d_ptr, 0, aspace.get_data(d_ptr, wordsz))

                    aspace.set_label(d_ptr + wordsz, "ELF.CUR_OBJ")
                    aspace.make_data(d_ptr + wordsz, wordsz)
                    aspace.set_comment(d_ptr + wordsz, "Identifier of this ELF object")

                    aspace.set_label(d_ptr + wordsz * 2, "ELF.SYM_LOOKUP")
                    aspace.make_data(d_ptr + wordsz * 2, wordsz)
                    aspace.set_comment(d_ptr + wordsz * 2, "Dynamic linker routine for symbol lookup")

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
                    print(reloc, sym.name, sym.entry)
                    symname = str(sym.name, "utf-8")
                    aspace.set_comment(pltrel, symname + ".plt")
                    aspace.make_arg_offset(pltrel, 0, aspace.get_data(pltrel, wordsz))

                    got_addr = reloc["r_offset"]
                    aspace.set_label(got_addr, symname + ".got")
                    aspace.make_data(got_addr, wordsz)
                    lazy_code = aspace.get_data(got_addr, wordsz)
                    aspace.make_arg_offset(got_addr, 0, lazy_code)

                    aspace.set_label(lazy_code, symname + ".lazy")
                    aspace.analisys_stack_push(lazy_code)

                    real_func = adjust_plt_addr(lazy_code)
                    aspace.set_label(real_func, symname)
                    aspace.analisys_stack_push(real_func)

                    pltrel += entry_struct.sizeof()

    return elffile["e_entry"]


def load_sections(aspace, elffile):
    wordsz = elffile.elfclass // 8
    is_exe = elffile["e_type"] == "ET_EXEC"
    addr_cnt = 0x10000
    sec_map = {}

    # As section order may be arbitrary, make sure to allocate allocatable sections first
    for i, sec in enumerate(elffile.iter_sections()):
        if sec["sh_flags"] & SH_FLAGS.SHF_ALLOC and sec["sh_size"]:
            name = str(sec.name, "ascii")
            size = sec["sh_size"]
            if is_exe:
                addr = sec["sh_addr"]
            else:
                addr = addr_cnt
            print(name, sec.header)
            access = sh_flags_to_access(sec["sh_flags"])
            aspace.add_area(addr, addr + size - 1, {"name": name, "access": access})
            if sec["sh_type"] == "SHT_PROGBITS":
                sec.stream.seek(sec['sh_offset'])
                aspace.load_content(sec.stream, addr, size)
            aspace.set_label(addr, name)
            sec_map[i] = (sec, addr)
            addr_cnt += size + 0xfff
            addr_cnt &= ~0xfff
            print()

    # Process symbols
    for _sec in elffile.iter_sections():
        if not isinstance(_sec, SymbolTableSection):
            continue

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
                aspace.set_label(sym["st_value"] + sec_start, symname)

                if sym["st_info"]["type"] == "STT_FUNC":
                    aspace.analisys_stack_push(sym["st_value"] + sec_start)
                if sym["st_info"]["type"] == "STT_OBJECT":
                    aspace.make_data_array(sym["st_value"] + sec_start, 1, sym["st_size"])

        break

    if is_exe:
        return elffile["e_entry"]

    R_XTENSA_32 = 1
    R_XTENSA_SLOT0_OP = 20
    R_XTENSA_ASM_EXPAND = 11

    for rel_sec in elffile.iter_sections():
        if not isinstance(rel_sec, RelocationSection):
            continue
        if rel_sec["sh_info"] not in sec_map:
            continue
        target_sec, addr = sec_map[rel_sec["sh_info"]]
        print(rel_sec.header, target_sec.name)
        for reloc in rel_sec.iter_relocations():
            print(reloc)

            sym = symtab[reloc['r_info_sym']]
            symname = str(sym.name, "utf-8")
            if reloc["r_addend"] != 0:
                symname += "+%d" % reloc["r_addend"]
            value = None
            sym_sec, sym_sec_addr = None, None
            if sym.entry["st_shndx"] != "SHN_UNDEF":
                sym_sec, sym_sec_addr = sec_map[sym.entry["st_shndx"]]
                value = sym.entry["st_value"] + sym_sec_addr + reloc["r_addend"]


            if reloc["r_info_type"] == R_XTENSA_32:
                aspace.set_comment(addr + reloc["r_offset"], "R_XTENSA_32: %s" % (symname))
                aspace.make_data(addr + reloc["r_offset"], wordsz)
                print(sym.entry)
                if value is not None:
                    sym_sec, sym_sec_addr = sec_map[sym.entry["st_shndx"]]
                    data = aspace.get_data(addr + reloc["r_offset"], wordsz)
                    data += value
                    aspace.set_data(addr + reloc["r_offset"], data, wordsz)
                    aspace.make_arg_offset(addr + reloc["r_offset"], 0, data)
            elif reloc["r_info_type"] == R_XTENSA_SLOT0_OP:
                aspace.set_comment(addr + reloc["r_offset"], "R_XTENSA_SLOT0_OP: %s" % (symname))
                opcode = aspace.get_byte(addr + reloc["r_offset"])
                if opcode & 0xf == 0x5:
                    # call
                    if value is not None:
                        p = addr + reloc["r_offset"]
                        value -= ((p & ~0x3) + 4)
                        assert value & 0x3 == 0
                        value = value >> 2
                        aspace.set_byte(p, (opcode & ~0xc0) | ((value << 6) & 0xc0))
                        aspace.set_byte(p + 1, value >> 2)
                        aspace.set_byte(p + 2, value >> 10)
                if opcode & 0xf == 0x1:
                    # l32r
                    pass
            elif reloc["r_info_type"] == R_XTENSA_ASM_EXPAND:
                aspace.set_comment(addr + reloc["r_offset"], "R_XTENSA_ASM_EXPAND: %s" % (symname))
            else:
                assert False, "Unknown reloc type: %d" % reloc["r_info_type"]
#        break



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
    class Stub:
        def __getattr__(self, attr):
            def dump(*a, **kw):
                print("AS.%s(%r, %s)" % (attr, a, kw))
                return 0
            return dump

    load(Stub(), sys.argv[1])
