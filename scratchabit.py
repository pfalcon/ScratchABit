# ScratchABit - interactive disassembler
#
# Copyright (c) 2015 Paul Sokolovsky
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import sys
import os
import os.path
import time
import re
import logging as log

import engine
import idaapi

import curses
import npyscreen
from pyedit import editorext as editor
import help


HEIGHT = 21

def disasm_one(p):
    insnsz = p.ana()
    p.out()
    print("%08x %s" % (p.cmd.ea, p.cmd.disasm))
    p.cmd.ea += p.cmd.size
    p.cmd.size = 0

class LabelEntry(npyscreen.Autocomplete):

    def set_choices(self, list):
        self.choices = [None] + list

    def auto_complete(self, input):
        substr = self.value
        self.choices[0] = substr
        choices = list(filter(lambda x: substr.lower() in x.lower(), self.choices))
        val = self.get_choice(choices)
        if val >= 0:
            self.value = choices[val]
            self.parent.exit_editing()


class Editor(editor.EditorExt):

    def __init__(self, *args):
        super().__init__(*args)
        self.model = None
        self.addr_stack = []

    def set_model(self, model):
        self.model = model
        self.set_lines(model.lines())
        # Invalidate top_line. Assuming goto_*() will be called
        # after set_model().
        self.top_line = sys.maxsize

    def show_line(self, l):
        if not isinstance(l, str):
            l = "%08x " % l.ea + l.indent + l.render()
        super().show_line(l)

    def goto_addr(self, to_addr, from_addr=None):
        if to_addr is None:
            self.show_status("No address-like value to go to")
            return

        # If we can position cursor within current screen, do that,
        # to avoid jumpy UI
        no = self.model.addr2line_no(to_addr)
        if no is not None:
            if self.line_visible(no):
                self.goto_line(no)
                if from_addr is not None:
                    self.addr_stack.append(from_addr)
                return

        # Otherwise, re-render model around needed address, and redraw screen
        t = time.time()
        model = engine.render_partial_around(to_addr, 0, HEIGHT * 2)
        self.show_status("Rendering time: %fs" % (time.time() - t))
        if not model:
            self.show_status("Unknown address: 0x%x" % to_addr)
            return
        self.set_model(model)

        no = self.model.addr2line_no(to_addr)
        if no is not None:
            if from_addr is not None:
                self.addr_stack.append(from_addr)
            if not self.goto_line(no):
                # Need to redraw always, because we changed underlying model
                self.update_screen()
        else:
            self.show_status("Unknown address: %x" % to_addr)

    def update_model(self):
        addr, subno = self.cur_addr_subno()
        t = time.time()
        model = engine.render_partial_around(addr, subno, HEIGHT * 2)
        self.show_status("Rendering time: %fs" % (time.time() - t))
        self.set_model(model)
        self.cur_line = model.target_addr_lineno
        self.top_line = self.cur_line - self.row
        self.update_screen()

    def handle_cursor_keys(self, key):
        if super().handle_cursor_keys(key):
            #log.debug("handle_cursor_keys: cur: %d, total: %d", self.cur_line, self.total_lines)
            if self.cur_line <= HEIGHT or self.total_lines - self.cur_line <= HEIGHT:
                log.debug("handle_cursor_keys: triggering update")
                self.update_model()

            return True
        else:
            return False

    def cur_addr(self):
        line = self.get_cur_line()
        return line.ea

    def cur_addr_subno(self):
        line = self.get_cur_line()
        return (line.ea, line.subno)

    def cur_operand_no(self, line):
        col = self.col - engine.ADDR_FIELD_SIZE - len(line.indent)
        #self.show_status("Enter pressed: %s, %s" % (col, line))
        for i, pos in enumerate(line.arg_pos):
            if pos[0] <= col <= pos[1]:
                return i
        return -1

    def analyze_status(self, cnt):
        self.show_status("Analyzing (%d insts so far)" % cnt)

    def handle_key(self, key):
        if key == editor.KEY_ENTER:
            line = self.get_cur_line()
            log.info("Enter pressed: %s" % line)
            op_no = self.cur_operand_no(line)
            self.show_status("Enter pressed: %s, %s" % (self.col, op_no))
            if isinstance(line, engine.DisasmObj):
                to_addr = None
                if op_no >= 0:
                    o = line[op_no]
                    to_addr = o.get_addr()
                if to_addr is None:
                    o = line.get_operand_addr()
                    if o:
                        to_addr = o.get_addr()
                self.goto_addr(to_addr, from_addr=line.ea)
        elif key == editor.KEY_ESC:
            if self.addr_stack:
                self.show_status("Returning")
                self.goto_addr(self.addr_stack.pop())
        elif key == b"q":
            return editor.KEY_QUIT
        elif key == b"c":
            addr = self.cur_addr()
            self.show_status("Analyzing at %x" % addr)
            engine.add_entrypoint(addr)
            engine.analyze(self.analyze_status)
            self.update_model()
        elif key == b"d":
            addr = self.cur_addr()
            fl = self.model.AS.get_flags(addr)
            if fl not in (self.model.AS.DATA, self.model.AS.UNK):
                self.show_status("Undefine first")
                return
            if fl == self.model.AS.UNK:
                self.model.AS.set_flags(addr, 1, self.model.AS.DATA, self.model.AS.DATA_CONT)
            else:
                sz = self.model.AS.get_unit_size(addr)
                self.model.undefine(addr)
                sz *= 2
                if sz > 4: sz = 1
                self.model.AS.set_flags(addr, sz, self.model.AS.DATA, self.model.AS.DATA_CONT)
            self.update_model()
        elif key == b"u":
            addr = self.cur_addr()
            self.model.undefine(addr)
            self.update_model()
        elif key == b"o":
            addr = self.cur_addr()
            line = self.get_cur_line()
            o = line.get_operand_addr()
            if not o:
                self.show_status("Cannot convert operand to offset")
                return
            if o.type != idaapi.o_imm or not self.model.AS.is_valid_addr(o.get_addr()):
                self.show_status("Cannot convert operand to offset: #%s: %s" % (o.n, o.type))
                return

            if self.model.AS.get_arg_prop(addr, o.n, "type") == idaapi.o_mem:
                self.model.AS.set_arg_prop(addr, o.n, "type", idaapi.o_imm)
                self.model.AS.del_xref(addr, o.get_addr(), idaapi.dr_O)
            else:
                self.model.AS.set_arg_prop(addr, o.n, "type", idaapi.o_mem)
                label = self.model.AS.get_label(o.get_addr())
                if not label:
                    self.model.AS.make_auto_label(o.get_addr())
                self.model.AS.add_xref(addr, o.get_addr(), idaapi.dr_O)
            self.update_model()
        elif key == b";":
            addr = self.cur_addr()
            comment = self.model.AS.get_comment(addr) or ""
            res = self.dialog_edit_line(line=comment, width=60)
            if res:
                self.model.AS.set_comment(addr, res)
            self.update_screen()
        elif key == b"n":
            addr = self.cur_addr()
            label = self.model.AS.get_label(addr)
            def_label = self.model.AS.get_default_label(addr)
            s = label or def_label
            res = self.dialog_edit_line(line=s)
            if res:
                if res == def_label:
                    res = addr
                self.model.AS.set_label(addr, res)
                if not label:
                    # If it's new label, we need to add it to model
                    self.update_model()
                    return
            self.update_screen()
        elif key == b"g":

            F = npyscreen.FormBaseNew(name='Go to', lines=6, columns=40, show_atx=4, show_aty=4)
            e = F.add(LabelEntry, name="Labels")
            e.set_choices(self.model.AS.get_label_list())

            def h_enter_key(input):
                if not e.value:
                    # Hitting Enter with empty text entry opens autocomplete dropbox
                    e.auto_complete(input)
                else:
                    F.exit_editing()
            e.add_handlers({curses.ascii.CR: h_enter_key})

            F.add(npyscreen.FixedText, value="Press Tab to auto-complete", editable=False)
            F.edit()
            res = self.model.AS.resolve_label(e.value)

            self.update_screen()
            self.goto_addr(res, from_addr=self.cur_addr())
        elif key == editor.KEY_F1:
            help.help(self)
            self.update_screen()
        elif key == b"S":
            save_state(project_dir)
            self.show_status("Saved.")


CPU_PLUGIN = None
ENTRYPOINTS = []

def filter_config_line(l):
    l = re.sub(r"#.*$", "", l)
    l = l.strip()
    return l

def load_symbols(fname):
    with open(fname) as f:
        for l in f:
            l = filter_config_line(l)
            if not l:
                continue
            m = re.search(r"\b([A-Za-z_$.][A-Za-z0-9_$.]*)\s*=\s*((0x)?[0-9A-Fa-f]+)", l)
            if m:
                #print(m.groups())
                ENTRYPOINTS.append((m.group(1), int(m.group(2), 0)))
            else:
                print("Warning: cannot parse entrypoint info from: %r" % l)

def parse_entrypoints(f):
    for l in f:
        l = filter_config_line(l)
        if not l:
            continue
        if l[0] == "[":
            return l
        m = re.match(r'load "(.+?)"', l)
        if m:
            load_symbols(m.group(1))
        else:
            label, addr = [v.strip() for v in l.split("=")]
            ENTRYPOINTS.append((label, int(addr, 0)))
    return ""

def parse_disasm_def(fname):
    global CPU_PLUGIN
    with open(fname) as f:
        for l in f:
            l = filter_config_line(l)
            if not l:
                continue
            #print(l)
            while True:
                if not l:
                    #return
                    break
                if l[0] == "[":
                    section = l[1:-1]
                    print("Processing section: %s" % section)
                    if section == "entrypoints":
                        l = parse_entrypoints(f)
                    else:
                        assert 0, "Unknown section: " + section
                else:
                    break

            if not l:
                break

            if l.startswith("load"):
                args = l.split()
                addr = int(args[2], 0)
                engine.ADDRESS_SPACE.load_content(addr, open(args[1], "rb"))
                print("Loading %s @0x%x" % (args[1], addr))
            elif l.startswith("cpu "):
                args = l.split()
                CPU_PLUGIN = __import__(args[1])
                print("Loading CPU plugin %s" % (args[1]))
            else:
                if "(" in l:
                    m = re.match(r"(.+?)\s*\(\s*(.+?)\s*\)\s+(.+)", l)
                    #print(m.groups())
                    start = int(m.group(1), 0)
                    end = start + int(m.group(2), 0) - 1
                    props = m.group(3)
                else:
                    m = re.match(r"(.+?)\s*-\s*(.+?)\s+(.+)", l)
                    #print(m.groups())
                    start = int(m.group(1), 0)
                    end = int(m.group(2), 0)
                    props = m.group(3)
                a = engine.ADDRESS_SPACE.add_area(start, end, props.upper())
                print("Adding area: %s" % engine.str_area(a))


def save_state(project_dir):
    if not os.path.isdir(project_dir):
        os.makedirs(project_dir)
    files = ["project.labels", "project.comments", "project.args", "project.xrefs", "project.aspace"]
    for fname in files:
        if os.path.exists(project_dir + "/" + fname):
            os.rename(project_dir + "/" + fname, project_dir + "/" + fname + ".bak")
    with open(project_dir + "/project.labels", "w") as f:
        engine.ADDRESS_SPACE.save_labels(f)
    with open(project_dir + "/project.comments", "w") as f:
        engine.ADDRESS_SPACE.save_comments(f)
    with open(project_dir + "/project.args", "w") as f:
        engine.ADDRESS_SPACE.save_arg_props(f)
    with open(project_dir + "/project.xrefs", "w") as f:
        engine.ADDRESS_SPACE.save_xrefs(f)
    with open(project_dir + "/project.aspace", "w") as f:
        engine.ADDRESS_SPACE.save_areas(f)

def load_state(project_dir):
    print("Loading state...")
    with open(project_dir + "/project.labels", "r") as f:
        engine.ADDRESS_SPACE.load_labels(f)
    with open(project_dir + "/project.comments", "r") as f:
        engine.ADDRESS_SPACE.load_comments(f)
    with open(project_dir + "/project.args", "r") as f:
        engine.ADDRESS_SPACE.load_arg_props(f)
    with open(project_dir + "/project.xrefs", "r") as f:
        engine.ADDRESS_SPACE.load_xrefs(f)
    with open(project_dir + "/project.aspace", "r") as f:
        engine.ADDRESS_SPACE.load_areas(f)


if __name__ == "__main__":
    sys.path.append("plugins")
    sys.path.append("plugins/cpu")
    parse_disasm_def(sys.argv[1])
    log.basicConfig(filename="scratchabit.log", format='%(asctime)s %(message)s', level=log.DEBUG)
    log.info("Started")

    p = CPU_PLUGIN.PROCESSOR_ENTRY()
    engine.set_processor(p)

    # Strip suffix if any from def filename
    project_name = sys.argv[1].rsplit(".", 1)[0]
    project_dir = project_name + ".scratchabit"

    if os.path.exists(project_dir + "/project.labels"):
        load_state(project_dir)
    else:
        for label, addr in ENTRYPOINTS:
            engine.add_entrypoint(addr)
            engine.ADDRESS_SPACE.set_label(addr, label)
        engine.analyze()

    #engine.print_address_map()

    if ENTRYPOINTS:
        show_addr = ENTRYPOINTS[0][1]
    else:
        show_addr = engine.ADDRESS_SPACE.min_addr()

    t = time.time()
    #_model = engine.render()
    _model = engine.render_partial_around(show_addr, 0, HEIGHT * 2)
    print("Rendering time: %fs" % (time.time() - t))
    #print(_model.lines())
    #sys.exit()

    e = Editor(1, 1, 78, 21)
    e.init_tty()
    e.cls()
    e.enable_mouse()
    e.draw_box(0, 0, 80, 23)
    e.set_model(_model)
    e.goto_addr(show_addr)
    e.loop()
    e.deinit_tty()
    e.wr("\n\n")
