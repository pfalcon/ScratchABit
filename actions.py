import engine


class TextSaveModel:
    def __init__(self, f, ctrl=None):
        self.f = f
        self.ctrl = ctrl
        self.cnt = 0
    def add_line(self, addr, line):
        line = ("%08x " % addr) + line.indent + line.render() + "\n"
        self.f.write(line)
        if self.ctrl and self.cnt % 256 == 0:
            self.ctrl.show_status("Writing: 0x%x" % addr)
        self.cnt += 1

def write_func(APP, addr, prefix="", feedback_obj=None):
    func = APP.aspace.lookup_func(addr)
    if func:
        funcname = APP.aspace.get_label(func.start)
        outfile = prefix + funcname + ".lst"
        with open(outfile, "w") as f:
            model = TextSaveModel(f, feedback_obj)
            for start, end in func.get_ranges():
                while start < end:
                    start = engine.render_from(model, start, 1)
        return outfile
