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
import argparse

import engine
import idaapi

import curses
from picotui.widgets import *
from picotui import editorext as editor
from picotui.screen import Screen
from picotui.editorext import Viewer
from picotui.menu import *
from picotui.dialogs import *
import utils
import help
import saveload
import uiprefs


HEIGHT = 21

MENU_PREFS = 2000
MENU_SCRIPT = 2001


class AppClass:
    pass

APP = AppClass()


def disasm_one(p):
    insnsz = p.ana()
    p.out()
    print("%08x %s" % (p.cmd.ea, p.cmd.disasm))
    p.cmd.ea += p.cmd.size
    p.cmd.size = 0


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


class Editor(editor.EditorExt):

    def __init__(self, *args):
        super().__init__(*args)
        self.model = None
        self.addr_stack = []
        self.search_str = ""

    def set_model(self, model):
        self.model = model
        self.set_lines(model.lines())
        # Invalidate top_line. Assuming goto_*() will be called
        # after set_model().
        self.top_line = sys.maxsize

    def show_line(self, l, i):
        global show_bytes
        res = l
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
        super().show_line(res, i)

    def goto_addr(self, to_addr, col=None, from_addr=None):
        if to_addr is None:
            self.show_status("No address-like value to go to")
            return
        subno = -1
        if isinstance(to_addr, tuple):
            to_addr, subno = to_addr
        adj_addr = self.model.AS.adjust_addr_reverse(to_addr)
        if adj_addr is None:
            self.show_status("Unknown address: 0x%x" % to_addr)
            return
        to_addr = adj_addr

        # If we can position cursor within current screen, do that,
        # to avoid jumpy UI
        no = self.model.addr2line_no(to_addr, subno)
        if no is not None:
            if self.line_visible(no):
                self.goto_line(no, col=col)
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

        no = self.model.addr2line_no(to_addr, subno)
        if no is not None:
            if from_addr is not None:
                self.addr_stack.append(from_addr)
            if not self.goto_line(no, col=col):
                # Need to redraw always, because we changed underlying model
                self.redraw()
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
        self.redraw()

    def handle_cursor_keys(self, key):
        cl = self.cur_line
        if super().handle_cursor_keys(key):
            if self.cur_line == cl:
                return True
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

    # Address of the next line. It may be the same address as the
    # current line, as several lines may "belong" to the same address,
    # (virtual lines like headers, etc.)
    def next_line_addr_subno(self):
        try:
            l = self.content[self.cur_line + 1]
            return (l.ea, l.subno)
        except:
            return None

    # Return next address following the current line. May need to skip
    # few virtual lines.
    def next_addr(self):
        addr = self.cur_addr()
        n = self.cur_line + 1
        try:
            while self.content[n].ea == addr:
                n += 1
            return self.content[n].ea
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

    def expect_flags(self, fl, allowed_flags):
        if fl not in allowed_flags:
            self.show_status("Undefine first (u key)")
            return False
        return True

    def write_func(self, addr):
        func = self.model.AS.lookup_func(addr)
        if func:
            funcname = self.model.AS.get_label(func.start)
            outfile = funcname + ".lst"
            with open(outfile, "w") as f:
                model = TextSaveModel(f, self)
                for start, end in func.get_ranges():
                    while start < end:
                        start = engine.render_from(model, start, 1)
            return outfile


    def handle_edit_key(self, key):
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
            self.redraw()


    def handle_key_unprotected(self, key):
        line = self.get_cur_line()
        if key == editor.KEY_ENTER:
            line = self.get_cur_line()
            log.info("Enter pressed: %s" % line)
            op_no = self.cur_operand_no(line)
            self.show_status("Enter pressed: %s, %s" % (self.col, op_no))
            to_addr = None
            # No longer try to jump only to addresses in args, parse
            # textual representation below
            if False and isinstance(line, engine.DisasmObj):
                if op_no >= 0:
                    o = line[op_no]
                    to_addr = o.get_addr()
                if to_addr is None:
                    o = line.get_operand_addr()
                    if o:
                        to_addr = o.get_addr()
            if to_addr is None:
                pos = self.col - line.LEADER_SIZE - len(line.indent)
                word = utils.get_word_at_pos(line.cache, pos)
                if word:
                    if word[0].isdigit():
                        to_addr = int(word, 0)
                    else:
                        to_addr = self.model.AS.resolve_label(word)
                        if to_addr is None:
                            self.show_status("Unknown address: %s" % word)
                            return
            self.goto_addr(to_addr, from_addr=self.cur_addr_subno())
        elif key == editor.KEY_ESC:
            if self.addr_stack:
                self.show_status("Returning")
                self.goto_addr(self.addr_stack.pop())
        elif key == b"q":
            return editor.KEY_QUIT
        elif key == b"\x1b[5;5~":  # Ctrl+PgUp
            self.goto_addr(self.model.AS.min_addr(), from_addr=line.ea)
        elif key == b"\x1b[6;5~":  # Ctrl+PgDn
            self.goto_addr(self.model.AS.max_addr(), from_addr=line.ea)
        elif key == b"c":
            addr = self.cur_addr()
            self.show_status("Analyzing at %x" % addr)
            engine.add_entrypoint(addr, False)
            engine.analyze(self.analyze_status)
            self.update_model()
        elif key == b"d":
            addr = self.cur_addr()
            fl = self.model.AS.get_flags(addr)
            if not self.expect_flags(fl, (self.model.AS.DATA, self.model.AS.UNK)):
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
            if not self.expect_flags(fl, (self.model.AS.DATA, self.model.AS.UNK)):
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
                if fl not in (self.model.AS.UNK, self.model.AS.DATA, self.model.AS.DATA_CONT):
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
        elif key == b"f":
            addr = self.cur_addr()
            fl = self.model.AS.get_flags(addr)
            if not self.expect_flags(fl, (self.model.AS.UNK,)):
                return

            sz = 0
            while True:
                try:
                    fl = self.model.AS.get_flags(addr)
                except engine.InvalidAddrException:
                    break
                if fl != self.model.AS.UNK:
                    break
                b = self.model.AS.get_byte(addr)
                if b not in (0, 0xff):
                    self.show_status("Filler must consist of 0x00 or 0xff")
                    return
                sz += 1
                addr += 1
            if sz > 0:
                self.model.AS.make_filler(self.cur_addr(), sz)
                self.update_model()

        elif key == b"u":
            addr = self.cur_addr()
            self.model.undefine_unit(addr)
            self.update_model()

        elif key == b"h":
            op_no = self.cur_operand_no(self.get_cur_line())
            if op_no >= 0:
                addr = self.cur_addr()
                subtype = self.model.AS.get_arg_prop(addr, op_no, "subtype")
                if subtype != engine.IMM_ADDR:
                    next_subtype = {
                        engine.IMM_UHEX: engine.IMM_UDEC,
                        engine.IMM_UDEC: engine.IMM_UHEX,
                    }
                    self.model.AS.set_arg_prop(addr, op_no, "subtype", next_subtype[subtype])
                    self.redraw()
                    self.show_status("Changed arg #%d to %s" % (op_no, next_subtype[subtype]))
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

            if self.model.AS.get_arg_prop(addr, o.n, "subtype") == engine.IMM_ADDR:
                self.model.AS.unmake_arg_offset(addr, o.n, o.get_addr())
            else:
                self.model.AS.make_arg_offset(addr, o.n, o.get_addr())
            self.update_model(True)
        elif key == b";":
            addr = self.cur_addr()
            comment = self.model.AS.get_comment(addr) or ""
            res = DMultiEntry(60, 5, comment.split("\n"), title="Comment:").result()
            if res != ACTION_CANCEL:
                res = "\n".join(res).rstrip("\n")
                self.model.AS.set_comment(addr, res)
                self.update_model()
            else:
                self.redraw()
        elif key == b"n":
            addr = self.cur_addr()
            label = self.model.AS.get_label(addr)
            def_label = self.model.AS.get_default_label(addr)
            s = label or def_label
            while True:
                res = DTextEntry(30, s, title="New label:").result()
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
            self.redraw()
        elif key == b"g":
            d = Dialog(4, 4, title="Go to")
            d.add(1, 1, WLabel("Label/addr:"))
            entry = WAutoComplete(20, "", self.model.AS.get_label_list())
            entry.popup_h = 12
            entry.finish_dialog = ACTION_OK
            d.add(13, 1, entry)
            d.add(1, 2, WLabel("Press Down to auto-complete"))
            res = d.loop()
            self.redraw()

            if res == ACTION_OK:
                value = entry.get_text()
                if '0' <= value[0] <= '9':
                    addr = int(value, 0)
                else:
                    addr = self.model.AS.resolve_label(value)
                self.goto_addr(addr, from_addr=self.cur_addr())

        elif key == editor.KEY_F1:
            help.help(self)
            self.redraw()
        elif key == b"S":
            self.show_status("Saving...")
            saveload.save_state(project_dir)
            self.show_status("Saved.")
        elif key == b"\x11":  # ^Q
            class IssueList(WListBox):
                def render_line(self, l):
                    return "%08x %s" % l
            d = Dialog(4, 4, title="Problems list")
            lw = IssueList(40, 16, self.model.AS.get_issues())
            lw.finish_dialog = ACTION_OK
            d.add(1, 1, lw)
            res = d.loop()
            self.redraw()
            if res == ACTION_OK:
                val = lw.get_cur_line()
                if val:
                    self.goto_addr(val[0], from_addr=self.cur_addr())

        elif key == b"i":
            off, area = self.model.AS.addr2area(self.cur_addr())
            props = area[engine.PROPS]
            percent = 100 * off / (area[engine.END] - area[engine.START] + 1)
            func = self.model.AS.lookup_func(self.cur_addr())
            func = self.model.AS.get_label(func.start) if func else None
            self.show_status("Area: 0x%x %s (%s): %.1f%%, func: %s" % (
                area[engine.START], props.get("name", "noname"), props["access"], percent, func
            ))
        elif key == b"I":
            L = 5
            T = 2
            W = 66
            H = 20
            self.dialog_box(L, T, W, H)
            v = Viewer(L + 1, T + 1, W - 2, H - 2)
            lines = []
            for area in self.model.AS.get_areas():
                props = area[engine.PROPS]
                lines.append("%08x-%08x %s:" % (area[engine.START], area[engine.END], props.get("name", "noname")))
                flags = area[engine.FLAGS]
                last_capital = None
                l = ""
                for i in range(len(flags)):
                    if i % 64 == 0 and l:
                        lines.append(l)
                        l = ""
                    c = engine.flag2char(flags[i])
                    # For "function's instructions", make continuation byte be
                    # clearly distinguishable too.
                    if c == "c" and last_capital == "F":
                        c = "f"
                    l += c
                    if c < "a":
                        last_capital = c
                if l:
                    lines.append(l)
            v.set_lines(lines)
            v.loop()
            self.redraw()
        elif key == b"W":
            out_fname = "out.lst"
            with open(out_fname, "w") as f:
                engine.render_partial(TextSaveModel(f, self), 0, 0, 10000000)
            self.show_status("Disassembly listing written: " + out_fname)
        elif key == b"\x17":  # Ctrl+W
            outfile = self.write_func(self.cur_addr())
            if outfile:
                self.show_status("Wrote file: %s" % outfile)
        elif key == b"\x15":  # Ctrl+U
            # Next undefined
            addr = self.cur_addr()
            flags = self.model.AS.get_flags(addr)
            if flags == self.model.AS.UNK:
                # If already on undefined, skip the current stride of them,
                # as they indeed go in batches.
                while True:
                    flags = self.model.AS.get_flags(addr)
                    if flags != self.model.AS.UNK:
                        break
                    addr = self.model.AS.next_addr(addr)
                    if addr is None:
                        break

            if addr is not None:
                while True:
                    flags = self.model.AS.get_flags(addr)
                    if flags == self.model.AS.UNK:
                        self.goto_addr(addr, from_addr=self.cur_addr())
                        break
                    addr = self.model.AS.next_addr(addr)
                    if addr is None:
                        break

            if addr is None:
                self.show_status("There're no further undefined strides")

        elif key in (b"/", b"?"):  # "/" and Shift+"/"

            class FoundException(Exception): pass

            class TextSearchModel(engine.Model):
                def __init__(self, substr, ctrl, this_addr, this_subno):
                    super().__init__()
                    self.search = substr
                    self.ctrl = ctrl
                    self.this_addr = this_addr
                    self.this_subno = this_subno
                    self.cnt = 0
                def add_line(self, addr, line):
                    super().add_line(addr, line)
                    # Skip virtual lines before the line from which we started
                    if addr == self.this_addr and line.subno < self.this_subno:
                        return
                    txt = line.render()
                    idx = txt.find(self.search)
                    if idx != -1:
                        raise FoundException((addr, line.subno), idx + line.LEADER_SIZE + len(line.indent))
                    if self.cnt % 256 == 0:
                        self.ctrl.show_status("Searching: 0x%x" % addr)
                    self.cnt += 1
                    # Don't accumulate lines
                    self._lines = []
                    self._addr2line = {}

            if key == b"/":
                d = Dialog(4, 4, title="Text Search")
                d.add(1, 1, WLabel("Search for:"))
                entry = WTextEntry(20, self.search_str)
                entry.finish_dialog = ACTION_OK
                d.add(13, 1, entry)
                res = d.loop()
                self.redraw()
                self.search_str = entry.get_text()
                if res != ACTION_OK or not self.search_str:
                    return
                addr, subno = self.cur_addr_subno()
            else:
                addr, subno = self.next_line_addr_subno()

            try:
                engine.render_from(TextSearchModel(self.search_str, self, addr, subno), addr, 10000000)
            except FoundException as res:
                self.goto_addr(res.args[0], col=res.args[1], from_addr=self.cur_addr())
            else:
                self.show_status("Not found: " + self.search_str)

        elif key == MENU_PREFS:
            uiprefs.handle(APP)

        elif key == MENU_SCRIPT:
            res = DTextEntry(30, "", title="Script module name:").result()
            if res:
                call_script(res)
                self.show_status("Script '%s' run successfully" % res)
                self.update_model()
            else:
                self.redraw()
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
                    print("Loading %s @0x%x" % (args[1], addr))
                    engine.ADDRESS_SPACE.load_content(open(args[1], "rb"), addr)
                else:
                    print("Loading %s (%s plugin)" % (args[1], args[2]))
                    loader = __import__(args[2])
                    load_target_file(loader, args[1])
            elif l.startswith("cpu "):
                args = l.split()
                CPU_PLUGIN = __import__(args[1])
                print("Loading CPU plugin %s" % (args[1]))
            elif l.startswith("show bytes "):
                args = l.split()
                show_bytes = int(args[2])
            elif l.startswith("area "):
                args = l.split()
                assert len(args) == 4

                # Allow undescores to separate digit groups
                def str2int(s):
                    return int(s.replace("_", ""), 0)

                if "(" in args[2]:
                    m = re.match(r"(.+?)\s*\(\s*(.+?)\s*\)", args[2])
                    start = str2int(m.group(1))
                    end = start + str2int(m.group(2)) - 1
                else:
                    m = re.match(r"(.+)\s*-\s*(.+)", args[2])
                    start = str2int(m.group(1))
                    end = str2int(m.group(2))

                a = engine.ADDRESS_SPACE.add_area(start, end, {"name": args[1], "access": args[3].upper()})
                print("Adding area: %s" % engine.str_area(a))
            else:
                assert 0, "Unknown directive: " + l


class MainScreen:

    def __init__(self):
        self.screen_size = Screen.screen_size()
        self.e = Editor(1, 2, self.screen_size[0] - 2, self.screen_size[1] - 4)

        menu_file = WMenuBox([
            ("Save (Shift+s)", b"S"), ("Write disasm (Shift+w)", b"W"),
            ("Write function (Ctrl+w)", b"\x17"),
            ("Quit (q)", b"q")
        ])
        menu_goto = WMenuBox([
            ("Follow (Enter)", KEY_ENTER), ("Return (Esc)", KEY_ESC),
            ("Goto... (g)", b"g"), ("Search disasm... (/)", b"/"),
            ("Search next (Shift+/)", b"?"), ("Next undefined (Ctrl+u)", b"\x15"),
        ])
        menu_edit = WMenuBox([
            ("Undefined (u)", b"u"), ("Code (c)", b"c"), ("Data (d)", b"d"),
            ("ASCII String (a)", b"a"), ("Filler (f)", b"f"), ("Make label (n)", b"n"),
            ("Number/Address (o)", b"o"), ("Hex/dec (h)", b"h"),
        ])
        menu_analysis = WMenuBox([
            ("Info (whereami) (i)", b"i"), ("Memory map (Shift+i)", b"I"),
            ("Run script...", MENU_SCRIPT),
            ("Preferences...", MENU_PREFS),
        ])
        menu_help = WMenuBox([
            ("Help (F1)", KEY_F1), ("About...", "about"),
        ])
        self.menu_bar = WMenuBar([
            ("File", menu_file), ("Goto", menu_goto), ("Edit", menu_edit),
            ("Analysis", menu_analysis), ("Help", menu_help)
        ])
        self.menu_bar.permanent = True

    def redraw(self):
        self.menu_bar.redraw()
        self.e.draw_box(0, 1, self.screen_size[0], self.screen_size[1] - 2)
        self.e.redraw()

    def loop(self):
        while 1:
            key = self.e.get_input()
            if isinstance(key, list):
                x, y = key
                if self.menu_bar.inside(x, y):
                    self.menu_bar.focus = True

            if self.menu_bar.focus:
                res = self.menu_bar.handle_input(key)
                if res == ACTION_CANCEL:
                    self.menu_bar.focus = False
                elif res is not None and res is not True:

                    res = self.e.handle_input(res)
                    if res is not None and res is not True:
                        return res
            else:
                if key == KEY_F9:
                    self.menu_bar.focus = True
                    self.menu_bar.redraw()
                    continue
                res = self.e.handle_input(key)
                if res is not None and res is not True:
                    return res


def call_script(script):
    mod = __import__(script)
    main_f = getattr(mod, "main", None)
    if main_f:
        main_f(APP)


if __name__ == "__main__":

    argp = argparse.ArgumentParser(description="ScratchABit interactive disassembler")
    argp.add_argument("file", help="Input file (binary or disassembly .def)")
    argp.add_argument("--script", action="append", help="Run script from file after loading environment")
    argp.add_argument("--save", action="store_true", help="Save after --script and quit; don't show UI")
    args = argp.parse_args()

    # Plugin dirs are relative to the dir where scratchabit.py resides.
    # sys.path[0] below provide absolute path of this dir, resolved for
    # symlinks.
    plugin_dirs = ["plugins", "plugins/cpu", "plugins/loader"]
    for d in plugin_dirs:
        sys.path.append(os.path.join(sys.path[0], d))
    log.basicConfig(filename="scratchabit.log", format='%(asctime)s %(message)s', level=log.DEBUG)
    log.info("Started")

    if args.file.endswith(".def"):
        parse_disasm_def(args.file)
        project_name = args.file.rsplit(".", 1)[0]
    else:
        import default_plugins
        for loader_id in default_plugins.loaders:
            loader = __import__(loader_id)
            arch_id = loader.detect(args.file)
            if arch_id:
                break
        if not arch_id:
            print("Error: file '%s' not recognized by default loaders" % args.file)
            sys.exit(1)
        if arch_id not in default_plugins.cpus:
            print("Error: no plugin for CPU '%s' as detected for file '%s'" % (arch_id, args.file))
            sys.exit(1)
        load_target_file(loader, args.file)
        CPU_PLUGIN = __import__(default_plugins.cpus[arch_id])
        project_name = args.file

    p = CPU_PLUGIN.PROCESSOR_ENTRY()
    if hasattr(p, "config"):
        p.config()
    engine.set_processor(p)
    if hasattr(p, "help_text"):
        help.set_cpu_help(p.help_text)
    APP.cpu_plugin = p
    APP.aspace = engine.ADDRESS_SPACE
    APP.is_ui = False

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

    if args.script:
        for script in args.script:
            call_script(script)
        if args.save:
            saveload.save_state(project_dir)
            sys.exit()

    addr_stack = []
    if os.path.exists(project_dir + "/session.addr_stack"):
        addr_stack = saveload.load_addr_stack(project_dir)
        print(addr_stack)
        show_addr = addr_stack.pop()
    else:
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

    Screen.init_tty()
    try:
        Screen.cls()
        Screen.enable_mouse()
        main_screen = MainScreen()
        APP.main_screen = main_screen
        APP.is_ui = True
        main_screen.e.set_model(_model)
        main_screen.e.addr_stack = addr_stack
        main_screen.e.goto_addr(show_addr)
        Screen.set_screen_redraw(main_screen.redraw)
        main_screen.redraw()
        main_screen.loop()
    except:
        log.exception("Unhandled exception")
        raise
    finally:
        Screen.goto(0, main_screen.screen_size[1])
        Screen.cursor(True)
        Screen.disable_mouse()
        Screen.deinit_tty()
        Screen.wr("\n\n")
        saveload.save_session(project_dir, main_screen.e)
