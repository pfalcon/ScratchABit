from pyelftools.elftools.elf.elffile import ELFFile

def load(aspace, fname):

    f = open(fname, "rb")
    elffile = ELFFile(f)
    #print(elffile)
    #print(elffile.header)
    #print("entry: %x" % elffile["e_entry"])
    #print()

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
            for s in seg.iter_symbols():
                if s["st_shndx"] != "SHN_UNDEF":
                    #print(s.name, hex(s["st_value"]), s.entry)
                    aspace.set_label(s["st_value"], str(s.name, "utf-8"))

                    if s["st_info"]["type"] == "STT_FUNC":
                        aspace.analisys_stack_push(s["st_value"])
                    if s["st_info"]["type"] == "STT_OBJECT":
                        # TODO: Set as data of given s["st_size"]
                        pass

    return elffile["e_entry"]
