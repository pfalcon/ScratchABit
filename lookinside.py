import idaapi
import xtensa

def disasm_one(p):
    insnsz = p.ana()
    p.out()
    print("%08x %s" % (p.cmd.ea, p.cmd.disasm))
    p.cmd.ea += p.cmd.size
    p.cmd.size = 0


idaapi.ADDRESS_SPACE.add_area(0x3FFE8000, 0x3FFFBFFF, "RW")
idaapi.ADDRESS_SPACE.add_area(0x3FFFC000, 0x3fffffff, "RW")
idaapi.ADDRESS_SPACE.add_area(0x40000000, 0x4000ffff, "RO")
idaapi.ADDRESS_SPACE.load_content(0x40000000, open("bootrom.bin", "rb"))

p = xtensa.PROCESSOR_ENTRY()
idaapi.set_processor(p)

entry = 0x40000080

#idaapi.add_entrypoint(0x40000080)
idaapi.add_entrypoint(0x40000010)
#idaapi.add_entrypoint(0x40000020)
#idaapi.add_entrypoint(0x40000030)
#idaapi.add_entrypoint(0x40000050)
#idaapi.add_entrypoint(0x40000070)
idaapi.analyze()

#idaapi.print_address_map()

_model = idaapi.render()

import editor

class Editor(editor.Editor):

    def __init__(self):
        super().__init__()
        self.model = None
        self.addr_stack = []

    def set_model(self, model):
        self.model = model
        self.set_lines(model.lines())

    def goto_addr(self, to_addr, from_addr=None):
        no = self.model.addr2line_no(to_addr)
        if no is not None:
            if from_addr is not None:
                self.addr_stack.append(from_addr)
            self.goto_line(no)
        else:
            self.show_status("Unknown address: %x" % to_addr)

    def cur_addr(self):
        line = self.get_cur_line()
        parts = line.split(None, 1)
        return int(parts[0], 16)

    def handle_key(self, key):
        if key == editor.KEY_ENTER:
            line = self.get_cur_line()
            self.show_status("Enter pressed: %s" % line)
            parts = line.split()
            if parts[-1].startswith("0x"):
                addr = int(parts[-1], 0)
                self.goto_addr(addr, from_addr=int(parts[0], 16))
        elif key == editor.KEY_ESC:
            if self.addr_stack:
                self.show_status("Returning")
                self.goto_addr(self.addr_stack.pop())
        elif key == b"q":
            return editor.KEY_QUIT
        elif key == b"c":
            addr = self.cur_addr()
            self.show_status("Analyzing at %x" % addr)
            idaapi.add_entrypoint(addr)
            def analyze_status(cnt):
                self.show_status("Analyzing at %x (%d insts so far)" % (addr, cnt))
            idaapi.analyze(analyze_status)
            model = idaapi.render()
            self.set_model(model)
            self.goto_addr(addr)


if 1:
    e = Editor()
    e.init_tty()
    e.enable_mouse()
    e.set_model(_model)
    e.goto_addr(entry)
    e.loop()
    e.deinit_tty()
