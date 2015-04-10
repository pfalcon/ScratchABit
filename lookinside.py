import sys
import time

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

idaapi.add_entrypoint(0x40000080)
idaapi.add_entrypoint(0x40000010)
#idaapi.add_entrypoint(0x40000020)
#idaapi.add_entrypoint(0x40000030)
#idaapi.add_entrypoint(0x40000050)
#idaapi.add_entrypoint(0x40000070)
idaapi.analyze()

#idaapi.print_address_map()

t = time.time()
#_model = idaapi.render()
_model = idaapi.render_partial_around(entry)
print("Rendering time: %fs" % (time.time() - t))
#print(_model.lines())
#sys.exit()

import editor_api as editor

class Editor(editor.EditorExt):

    def __init__(self):
        super().__init__()
        self.model = None
        self.addr_stack = []

    def set_model(self, model):
        self.model = model
        self.set_lines(model.lines())

    def show_line(self, l):
        if not isinstance(l, str):
            l = "%08x " % l.ea +  l.render()
        super().show_line(l)

    def goto_addr(self, to_addr, from_addr=None):
        model = idaapi.render_partial_around(to_addr)
        self.set_model(model)

        no = self.model.addr2line_no(to_addr)
        if no is not None:
            if from_addr is not None:
                self.addr_stack.append(from_addr)
            self.goto_line(no)
        else:
            self.show_status("Unknown address: %x" % to_addr)

    def handle_cursor_keys(self, key):
        if super().handle_cursor_keys(key):
            if self.cur_line < 5 or self.total_lines - self.cur_line < 5:
                addr = self.cur_addr()
                model = idaapi.render_partial_around(addr)
                self.set_model(model)
                self.cur_line = model.target_addr_lineno
                self.top_line = self.cur_line - self.row

                self.show_status("Triggered model update")
            return True
        else:
            return False

    def cur_addr(self):
        line = self.get_cur_line()
        if isinstance(line, str):
            parts = line.split(None, 1)
            return int(parts[0], 16)
        return line.ea

    def analyze_status(self, cnt):
        self.show_status("Analyzing (%d insts so far)" % cnt)

    def handle_key(self, key):
        if key == editor.KEY_ENTER:
            line = self.get_cur_line()
            self.show_status("Enter pressed: %s" % line)
            if isinstance(line, idaapi.insn_t):
                o = line.get_operand_addr()
                if o:
                    self.goto_addr(o.addr, from_addr=line.ea)
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
            idaapi.analyze(self.analyze_status)
            t = time.time()
            model = idaapi.render()
            self.show_status("Rendering time: %fs" % (time.time() - t))
            self.set_model(model)
            self.goto_addr(addr)
        elif key == b"u":
            addr = self.cur_addr()
            self.model.undefine(addr)
            t = time.time()
            model = idaapi.render()
            self.show_status("Rendering time: %fs" % (time.time() - t))
            self.set_model(model)
            self.goto_addr(addr)
        elif key == b"n":
            addr = self.cur_addr()
            label = self.model.AS.get_label(addr)
            s = label or ""
            res = self.dialog_edit_line(line=s)
            if res:
                self.model.AS.set_label(addr, res)
                if not label:
                    # If it's new label, we need to add it to model
                    self.model.insert_vline(self.cur_line, addr, idaapi.Label(addr))
            self.update_screen()


if 1:
    e = Editor()
    e.init_tty()
    e.enable_mouse()
    e.set_model(_model)
    e.goto_addr(entry)
    e.loop()
    e.deinit_tty()
