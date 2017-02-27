import bisect

from picotui.editorext import EditorExt, CharColorViewer
# Keys and colors
from picotui.screen import *
from . import engine


L = 5
T = 2
W = 66
H = 20

COLOR_MAP = {
    "F": C_PAIR(C_GREEN, C_BLUE),
    "f": C_PAIR(C_GREEN, C_BLUE),
    "-": C_PAIR(C_GRAY, C_BLUE),
    "D": C_PAIR(C_MAGENTA, C_BLUE),
    "d": C_PAIR(C_MAGENTA, C_BLUE),
    "X": C_PAIR(C_B_RED, C_BLUE),
}

# EditorExt with Viewer's key handling
class MemMapViewer(EditorExt, CharColorViewer):
    pass


def show(AS, cur_addr):
    v = MemMapViewer(L + 1, T + 1, W - 2, H - 2)
    v.attr_color(C_B_WHITE, C_BLUE)
    v.dialog_box(L, T, W, H)
    lines = []
    addr_list = []
    def_c = C_PAIR(C_CYAN, C_BLUE)
    for area in AS.get_areas():
        props = area[engine.PROPS]
        flags = area[engine.FLAGS]
        addr = area[engine.START]
        last_capital = None
        lines.append([
            ("%08x-%08x %s:" % (addr, area[engine.END], props.get("name", "noname")),
                C_PAIR(C_B_YELLOW, C_BLUE))
        ])
        addr_list.append(addr)

        l = []
        for i in range(len(flags)):
            if i % 64 == 0 and l:
                lines.append(l)
                addr_list.append(addr)
                l = []
                addr += 64
            c = engine.flag2char(flags[i])
            # For "function's instructions", make continuation byte be
            # clearly distinguishable too.
            if c == "c" and last_capital == "F":
                c = "f"
            l.append((c, COLOR_MAP.get(c, def_c)))
            if c < "a":
                last_capital = c
        if l:
            lines.append(l)
            addr_list.append(addr)

    v.set_lines(lines)
    v.set_def_color(def_c)

    i = bisect.bisect_right(addr_list, cur_addr)
    v.goto_line(i - 1, cur_addr - addr_list[i - 1])

    if v.loop() == KEY_ENTER:
        return addr_list[v.cur_line] + v.col
