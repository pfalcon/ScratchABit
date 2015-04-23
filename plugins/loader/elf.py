from pyelftools.elftools.elf.elffile import ELFFile

def load(aspace, fname):

    f = open(fname, "rb")
    elffile = ELFFile(f)
    #print(elffile)
    #print(elffile.header)
    #print("entry: %x" % elffile["e_entry"])
    #print()

    for seg in elffile.iter_segments():
        if seg["p_type"] != "PT_LOAD":
            continue
        #print(seg)
        #print(seg.header)
        #print("p_vaddr=%x p_memsz=%x" % (seg["p_vaddr"], seg["p_memsz"]))
        #print()
        aspace.add_area(seg["p_vaddr"], seg["p_vaddr"] + seg["p_memsz"] - 1, "TODO")
        seg.stream.seek(seg['p_offset'])
        aspace.load_content(seg.stream, seg["p_vaddr"], seg["p_filesz"])

    return elffile["e_entry"]
