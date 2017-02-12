import bisect

from picotui.editorext import EditorExt, Viewer
from . import engine


L = 5
T = 2
W = 66
H = 20


# EditorExt with Viewer's key handling
class MemMapViewer(EditorExt, Viewer):
    pass


def show(AS, cur_addr):
    v = MemMapViewer(L + 1, T + 1, W - 2, H - 2)
    v.dialog_box(L, T, W, H)
    lines = []
    addr_list = []
    for area in AS.get_areas():
        props = area[engine.PROPS]
        flags = area[engine.FLAGS]
        addr = area[engine.START]
        last_capital = None
        lines.append("%08x-%08x %s:" % (addr, area[engine.END], props.get("name", "noname")))
        addr_list.append(addr)

        l = ""
        for i in range(len(flags)):
            if i % 64 == 0 and l:
                lines.append(l)
                addr_list.append(addr)
                l = ""
                addr += 64
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
            addr_list.append(addr)

    v.set_lines(lines)

    i = bisect.bisect_right(addr_list, cur_addr)
    v.goto_line(i - 1)

    v.loop()
