from picotui.widgets import *
from picotui import dialogs

from . import engine


class TextSaveModel:
    def __init__(self, f, ctrl=None, comments=True):
        self.f = f
        self.ctrl = ctrl
        self.cnt = 0
        self.comments = comments
    def add_line(self, addr, line):
        txt = line.render()
        if not self.comments and ";" in txt:
            txt = txt.rsplit(";", 1)[0].rstrip()
            if not txt.strip():
                return
        line = ("%08x " % addr) + line.indent + txt + "\n"
        self.f.write(line)
        if self.ctrl and self.cnt % 256 == 0:
            self.ctrl.show_status("Writing: 0x%x" % addr)
        self.cnt += 1


def write_func_stream(APP, func, stream, feedback_obj=None, comments=True):
    model = TextSaveModel(stream, feedback_obj, comments=comments)
    for start, end in func.get_ranges():
        while start < end:
            start = engine.render_from(model, start, 1)


def write_func_by_addr(APP, addr, prefix="", feedback_obj=None):
    func = APP.aspace.lookup_func(addr)
    if func:
        funcname = APP.aspace.get_label(func.start)
        outfile = prefix + funcname + ".lst"
        with open(outfile, "w") as f:
            write_func_stream(APP, func, f, feedback_obj)
        return outfile


def add_code_to_func(APP, addr):
    AS = APP.aspace
    fl = AS.get_flags(addr, 0xff)
    if not APP.main_screen.e.require_non_func(fl):
        return False

    insn_num = 0
    start_addr = addr
    while AS.get_flags(addr, 0xff) == AS.CODE:
        addr += AS.get_unit_size(addr)
        insn_num += 1

    d = Dialog(4, 4, title="Add to function")
    d.add(1, 1, WLabel("Marking %d instructions (%d bytes) as belonging" % (insn_num, addr - start_addr)))
    d.add(1, 2, WLabel("to a function. You may need to do this manually"))
    d.add(1, 3, WLabel("if a function uses indirect jumps."))
    d.add(1, 5, WLabel("Function:"))

    # By default pre-select function which bound-boxes this address
    func = AS.lookup_func(start_addr)
    func = AS.get_label(func.start) if func else ""

    entry = WAutoComplete(20, func, AS.get_func_list())
    entry.popup_h = 12
    entry.finish_dialog = ACTION_OK
    d.add(13, 5, entry)
    d.add(1, 6, WLabel("Press Down to auto-complete"))
    dialogs.add_ok_cancel_buttons(d)
    res = d.loop()

    if res != ACTION_OK:
        # Redraw
        return True

    value = entry.get_text()
    func_addr = AS.resolve_label(value)

    func = AS.get_func_start(func_addr)
    func.add_range(start_addr, addr)
    AS.mark_func_bytes(start_addr, addr - start_addr)

    return True
