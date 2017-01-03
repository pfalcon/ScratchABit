#
# This is a plugin which resolves "indirect jumps/calls to long location"
# as present in some RISC architectures. Specifically, for PseudoC sequence
# of:
#
# $a0 = value
# call $a0
#
# "value" will be marked as being an address, and sequence above will be
# marked as having a "call" xref to "value" address.
#
# This plugin was tested only on Xtensa architecture so far, and may need
# tweaks for other archs.
#
import sys
import engine
import idaapi


aspace = engine.ADDRESS_SPACE

def inst_in_area(area):
    addr = area[engine.START]
    end = area[engine.END] + 1
    while addr < end:
        fl = aspace.get_flags(addr)
        if fl == engine.ADDRESS_SPACE.CODE:
            inst = engine.Instruction(addr)
            engine._processor.cmd = inst
            sz = engine._processor.ana()
            engine._processor.out()
            yield inst
            addr += sz
        else:
            addr += 1


def main(APP):
    conv_imm = 0
    unconv_imm = 0

    for area in aspace.get_areas():
        if not "X" in area[engine.PROPS].get("access", ""):
            continue
        #print(area[:-2])
        last_inst = None
        for i in inst_in_area(area):
            if last_inst and i.disasm in ("goto $a0", "call $a0") and last_inst.disasm.startswith("$a0 = "):
                if last_inst[2].type == idaapi.o_imm:
                    if not APP.is_ui:
                        print(last_inst)
                        print(i)
                    target_addr = last_inst[2].get_addr()

                    # Change 1
                    if not APP.aspace.is_arg_offset(last_inst.ea, 2):
                        APP.aspace.make_arg_offset(last_inst.ea, 2, target_addr)
                        conv_imm += 1
                    else:
                        unconv_imm += 1

                    # Change 2
                    # Note: side effect of this is that of sequence
                    #   $a0 = sym
                    #   call $a0
                    # "$a0 = sym" will be marked as having "c" (call) xref to sym,
                    # whereas before this plugin run, the same line had "o" xref.
                    # More formally correct approach would be to make "call $a0"
                    # line to have "c" xref, but this would lead to doubling size of
                    # xref list. So, this entire situation is considered a feature, not
                    # a bug, and indeed what a user wants (and 2 instructions above
                    # can be considered a single compound instruction anyway).
                    idaapi.ua_add_cref(0, target_addr, idaapi.fl_CN if i.disasm[0] == "c" else idaapi.fl_JN)

            last_inst = i

    engine.analyze(lambda c: print(c))

    if not APP.is_ui:
        print("Immediates converted to offsets: %d, already converted: %d" % (conv_imm, unconv_imm))
        print("Done, press Enter")
        input()

#sys.exit()
