from pyelftools.elftools.elf.elffile import ELFFile
from pyelftools.elftools.elf.relocation import Relocation
from pyelftools.elftools.elf.enums import ENUM_D_TAG

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


def load_exe(aspace, elffile):
    wordsz = elffile.elfclass // 8

    for seg in elffile.iter_segments():
        #print(seg)
        #print(seg.header)
        #print("p_vaddr=%x p_memsz=%x" % (seg["p_vaddr"], seg["p_memsz"]))
        #print()
        if seg["p_type"] == "PT_LOAD":
            aspace.add_area(seg["p_vaddr"], seg["p_vaddr"] + seg["p_memsz"] - 1, "TODO")
            seg.stream.seek(seg['p_offset'])
            aspace.load_content(seg.stream, seg["p_vaddr"], seg["p_filesz"])
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


def load(aspace, fname):

    f = open(fname, "rb")
    elffile = ELFFile(f)
    #print(elffile)
    #print(elffile.header)
    #print("entry: %x" % elffile["e_entry"])
    #print()

    if elffile.num_segments():
        return load_exe(aspace, elffile)

    assert False, "No ELF segments found"


if __name__ == "__main__":
    import sys
    class Stub:
        def __getattr__(self, attr):
            return lambda *a, **kw: None

    load(Stub(), sys.argv[1])
