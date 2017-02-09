from picotui.editorext import Viewer
from . import engine


L = 5
T = 2
W = 66
H = 20

def show(AS):
    v = Viewer(L + 1, T + 1, W - 2, H - 2)
    v.dialog_box(L, T, W, H)
    lines = []
    for area in AS.get_areas():
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
