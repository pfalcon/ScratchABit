#!/usr/bin/env python3
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
import string
import binascii
import logging as log

import engine
import idaapi

import curses
import npyscreen
from pyedit import editorext as editor
import help
import saveload


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
        self.search_str = None

    def set_model(self, model):
        self.model = model
        self.set_lines(model.lines())
        # Invalidate top_line. Assuming goto_*() will be called
        # after set_model().
        self.top_line = sys.maxsize

    def show_line(self, l):
        global show_bytes
        if not isinstance(l, str):
            res = "%08x " % l.ea
            if show_bytes > 0:
                bin = ""
                if not l.virtual:
                    b = self.model.AS.get_bytes(l.ea, l.size)
                    bin = str(binascii.hexlify(b[:show_bytes]), "ascii")
                    if l.size > show_bytes:
                        bin += "+"
                res += idaapi.fillstr(bin, show_bytes * 2 + 1)
            res += l.indent + l.render()
        super().show_line(res)

    def goto_addr(self, to_addr, from_addr=None):
        if to_addr is None:
            self.show_status("No address-like value to go to")
            return
        adj_addr = self.model.AS.adjust_addr_reverse(to_addr)
        if adj_addr is None:
            self.show_status("Unknown address: 0x%x" % to_addr)
            return
        to_addr = adj_addr

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

    def update_model(self, stay_on_real=False):
        """Re-render model and update screen in such way that cursor stayed
        on the same line (as far as possible).
        stay_on_real == False - try to stay on same relative line no. for
        the current address.
        stay_on_real == True - try to stay on the line which contains real
        bytes for the current address (use this if you know that cursor
        stayed on such line before the update).
        """
        addr, subno = self.cur_addr_subno()
        t = time.time()
        model = engine.render_partial_around(addr, subno, HEIGHT * 2)
        self.show_status("Rendering time: %fs" % (time.time() - t))
        self.set_model(model)
        if stay_on_real:
            self.cur_line = model.target_addr_lineno_real
        else:
            self.cur_line = model.target_addr_lineno
        self.top_line = self.cur_line - self.row
        #log.debug("update_model: addr=%x, row=%d, cur_line=%d, top_line=%d" % (addr, self.row, self.cur_line, self.top_line))
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

    def next_addr(self):
        try:
            return self.content[self.cur_line + 1].ea
        except:
            return None

    def cur_addr_subno(self):
        line = self.get_cur_line()
        return (line.ea, line.subno)

    def cur_operand_no(self, line):
        col = self.col - engine.DisasmObj.LEADER_SIZE - len(line.indent)
        #self.show_status("Enter pressed: %s, %s" % (col, line))
        for i, pos in enumerate(line.arg_pos):
            if pos[0] <= col <= pos[1]:
                return i
        return -1

    def analyze_status(self, cnt):
        self.show_status("Analyzing (%d insts so far)" % cnt)

    def handle_key(self, key):
        try:
            return self.handle_key_unprotected(key)
        except Exception as e:
            log.exception("Exception processing user command")
            L = 5
            T = 2
            W = 70
            H = 20
            self.dialog_box(L, T, W, H)
            v = Viewer(L + 1, T + 1, W - 2, H - 2)
            import traceback
            v.set_lines([
                "Exception occured processing the command. Press Esc to continue.",
                "Recommended action is saving database, quitting and comparing",
                "database files with backup copies for possibility of data loss",
                "or corruption. The exception was also logged to scratchabit.log.",
                "Please report way to reproduce it to",
                "https://github.com/pfalcon/ScratchABit/issues",
                "",
            ] + traceback.format_exc().splitlines())
            v.loop()
            self.update_screen()


    def handle_key_unprotected(self, key):
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
            engine.add_entrypoint(addr, False)
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
                self.model.undefine_unit(addr)
                sz *= 2
                if sz > 4: sz = 1
                self.model.AS.set_flags(addr, sz, self.model.AS.DATA, self.model.AS.DATA_CONT)
            self.update_model()
        elif key == b"a":
            addr = self.cur_addr()
            fl = self.model.AS.get_flags(addr)
            if fl != self.model.AS.UNK:
                self.show_status("Undefine first")
                return
            sz = 0
            label = "s_"
            while True:
                b = self.model.AS.get_byte(addr)
                fl = self.model.AS.get_flags(addr)
                if not (0x20 <= b <= 0x7e or b in (0x0a, 0x0d)):
                    if b == 0:
                        sz += 1
                    break
                if fl != self.model.AS.UNK:
                    break
                c = chr(b)
                if c < '0' or c in string.punctuation:
                    c = '_'
                label += c
                addr += 1
                sz += 1
            if sz > 0:
                self.model.AS.set_flags(self.cur_addr(), sz, self.model.AS.STR, self.model.AS.DATA_CONT)
                self.model.AS.make_unique_label(self.cur_addr(), label)
                self.update_model()
        elif key == b"u":
            addr = self.cur_addr()
            self.model.undefine_unit(addr)
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
                self.model.AS.make_arg_offset(addr, o.n, o.get_addr())
            self.update_model(True)
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
            while True:
                res = self.dialog_edit_line(line=s)
                if not res:
                    break
                if res == def_label:
                    res = addr
                else:
                    if self.model.AS.label_exists(res):
                        s = res
                        self.show_status("Duplicate label")
                        continue
                self.model.AS.set_label(addr, res)
                if not label:
                    # If it's new label, we need to add it to model
                    self.update_model()
                    return
                break
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
            self.update_screen()
            if e.value:
                if '0' <= e.value[0] <= '9':
                    res = int(e.value, 0)
                else:
                    res = self.model.AS.resolve_label(e.value)

                self.goto_addr(res, from_addr=self.cur_addr())
        elif key == editor.KEY_F1:
            help.help(self)
            self.update_screen()
        elif key == b"S":
            saveload.save_state(project_dir)
            self.show_status("Saved.")
        elif key == b"\x11":  # ^Q
            F = npyscreen.Popup(name='Problems list', lines=18)
            class IssueList(npyscreen.MultiLine):
                def display_value(self, vl):
                    return "%08x %s" % vl
            lw = F.add(IssueList, name="Problems")
            #lw.return_exit = True
            lw.values = self.model.AS.get_issues()
            lw.add_handlers({curses.ascii.CR: lambda key: (lw.h_select_exit(key), F.exit_editing(), 1)})
            F.edit()
            self.update_screen()
            if lw.value is not None:
                val = lw.values[lw.value][0]
                self.goto_addr(val, from_addr=self.cur_addr())
        elif key == b"i":
            off, area = self.model.AS.addr2area(self.cur_addr())
            props = area[engine.PROPS]
            percent = 100 * off / (area[engine.END] - area[engine.START] + 1)
            func = self.model.AS.lookup_func(self.cur_addr())
            func = self.model.AS.get_label(func.start) if func else None
            self.show_status("Area: 0x%x %s (%s): %.1f%%, func: %s" % (
                area[engine.START], props.get("name", "noname"), props["access"], percent, func
            ))
        elif key == b"W":
            class TextSaveModel:
                def __init__(self, f, ctrl):
                    self.f = f
                    self.ctrl = ctrl
                    self.cnt = 0
                def add_line(self, addr, line):
                    line = ("%08x " % addr) + line.indent + line.render() + "\n"
                    self.f.write(line)
                    if self.cnt % 256 == 0:
                        self.ctrl.show_status("Writing: 0x%x" % addr)
                    self.cnt += 1
            out_fname = "out.lst"
            with open(out_fname, "w") as f:
                engine.render_partial(TextSaveModel(f, self), 0, 0, 10000000)
            self.show_status("Disassembly listing written: " + out_fname)
        elif key in (b"/", b"?"):  # "/" and Shift+"/"
            class FoundException(Exception): pass
            class TextSearchModel:
                def __init__(self, substr, ctrl):
                    self.search = substr
                    self.ctrl = ctrl
                    self.cnt = 0
                def add_line(self, addr, line):
                    line = line.render()
                    if self.search in line:
                        raise FoundException(addr)
                    if self.cnt % 256 == 0:
                        self.ctrl.show_status("Searching: 0x%x" % addr)
                    self.cnt += 1
            if key == b"/":
                F = npyscreen.FormBaseNew(name='Text Search', lines=5, columns=40, show_atx=4, show_aty=4)
                e = F.add(npyscreen.TitleText, name="Search for:")
                e.entry_widget.add_handlers({curses.ascii.CR: lambda k: F.exit_editing()})
                F.edit()
                self.update_screen()
                self.search_str = e.value
                addr = self.cur_addr()
            else:
                addr = self.next_addr()

            try:
                engine.render_from(TextSearchModel(self.search_str, self), addr, 10000000)
            except FoundException as res:
                self.goto_addr(res.args[0], from_addr=self.cur_addr())
            else:
                self.show_status("Not found: " + self.search_str)

        else:
            self.show_status("Unbound key: " + repr(key))


CPU_PLUGIN = None
ENTRYPOINTS = []
show_bytes = 0

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


def load_target_file(loader, fname):
    entry = loader.load(engine.ADDRESS_SPACE, fname)
    log.info("Loaded %s, entrypoint: %s", fname, hex(entry) if entry is not None else None)
    if entry is not None:
        ENTRYPOINTS.append(("_ENTRY_", entry))


def parse_disasm_def(fname):
    global CPU_PLUGIN
    global show_bytes
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
                if args[2][0] in string.digits:
                    addr = int(args[2], 0)
                    engine.ADDRESS_SPACE.load_content(open(args[1], "rb"), addr)
                    print("Loading %s @0x%x" % (args[1], addr))
                else:
                    loader = __import__(args[2])
                    load_target_file(loader, args[1])
            elif l.startswith("cpu "):
                args = l.split()
                CPU_PLUGIN = __import__(args[1])
                print("Loading CPU plugin %s" % (args[1]))
            elif l.startswith("show bytes "):
                args = l.split()
                show_bytes = int(args[2])
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
                a = engine.ADDRESS_SPACE.add_area(start, end, {"access": props.upper()})
                print("Adding area: %s" % engine.str_area(a))


if __name__ == "__main__":
    # Plugin dirs are relative to the dir where scratchabit.py resides.
    # sys.path[0] below provide absolute path of this dir, resolved for
    # symlinks.
    plugin_dirs = ["plugins", "plugins/cpu", "plugins/loader"]
    for d in plugin_dirs:
        sys.path.append(os.path.join(sys.path[0], d))
    log.basicConfig(filename="scratchabit.log", format='%(asctime)s %(message)s', level=log.DEBUG)
    log.info("Started")

    if sys.argv[1].endswith(".def"):
        parse_disasm_def(sys.argv[1])
        project_name = sys.argv[1].rsplit(".", 1)[0]
    else:
        import default_plugins
        for loader_id in default_plugins.loaders:
            loader = __import__(loader_id)
            arch_id = loader.detect(sys.argv[1])
            if arch_id:
                break
        if not arch_id:
            print("Error: file '%s' not recognized by default loaders" % sys.argv[1])
            sys.exit(1)
        if arch_id not in default_plugins.cpus:
            print("Error: no plugin for CPU '%s' as detected for file '%s'" % (arch_id, sys.argv[1]))
            sys.exit(1)
        load_target_file(loader, sys.argv[1])
        CPU_PLUGIN = __import__(default_plugins.cpus[arch_id])
        project_name = sys.argv[1]

    p = CPU_PLUGIN.PROCESSOR_ENTRY()
    engine.set_processor(p)
    if hasattr(p, "help_text"):
        help.set_cpu_help(p.help_text)

    engine.DisasmObj.LEADER_SIZE = 8 + 1
    if show_bytes:
        engine.DisasmObj.LEADER_SIZE += show_bytes * 2 + 1

    # Strip suffix if any from def filename
    project_dir = project_name + ".scratchabit"

    if saveload.save_exists(project_dir):
        saveload.load_state(project_dir)
    else:
        for label, addr in ENTRYPOINTS:
            if engine.ADDRESS_SPACE.is_exec(addr):
                engine.add_entrypoint(addr)
            engine.ADDRESS_SPACE.make_unique_label(addr, label)
        def _progress(cnt):
            sys.stdout.write("Performing initial analysis... %d\r" % cnt)
        engine.analyze(_progress)
        print()

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

    Editor.init_tty()
    try:
        screen_size = Editor.screen_size()
        e = Editor(1, 1, screen_size[0] - 2, screen_size[1] - 3)
        e.cls()
        e.enable_mouse()
        e.draw_box(0, 0, screen_size[0], screen_size[1] - 1)
        e.set_model(_model)
        e.goto_addr(show_addr)
        e.loop()
    except:
        log.exception("Unhandled exception")
        raise
    finally:
        e.cursor(True)
        e.deinit_tty()
        e.wr("\n\n")
