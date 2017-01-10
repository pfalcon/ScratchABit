import sys
import os
import glob

from . import engine


def save_exists(project_dir):
    files = list(glob.glob(project_dir + "/project.aspace*"))
    return bool(files)


def ensure_project_dir(project_dir):
    if not os.path.isdir(project_dir):
        os.makedirs(project_dir)

def backup_by_prefix(prefix):
    for fname in glob.glob(prefix):
        if not fname.endswith(".bak"):
            os.rename(fname, fname + ".bak")

def save_state(project_dir):
    ensure_project_dir(project_dir)
    files = ["project.aspace", "project.aprops"]
    for fname in files:
        backup_by_prefix(project_dir + "/" + fname + "*")

    for area in engine.ADDRESS_SPACE.get_areas():
        with open(project_dir + "/project.aspace.%08x" % area[engine.START], "w") as f:
            engine.ADDRESS_SPACE.save_area(f, area)

    engine.ADDRESS_SPACE.save_addr_props(project_dir + "/project.aprops")


def load_state(project_dir):
    files = list(glob.glob(project_dir + "/project.aprops*"))
    if not files:
        print("""
Cannot find project.aprops file. Possibly, you use old database format.
Use version 0.9 to migrate.
""")
        sys.exit(1)

    print("Loading state...")

    for area in engine.ADDRESS_SPACE.get_areas():
        fname = project_dir + "/project.aspace.%08x" % area[engine.START]
        with open(fname) as f:
            engine.ADDRESS_SPACE.load_area(f, area)

        fname = project_dir + "/project.aprops.%08x" % area[engine.START]
        if os.path.exists(fname):
            with open(fname) as f:
                engine.ADDRESS_SPACE.load_addr_props(f)
        else:
            print("Warning: %s doesn't exist" % fname)


# Save user-specific session parameter, like current address,
# address goto stack.
def save_session(project_dir, disasm_viewer):
    ensure_project_dir(project_dir)
    with open(project_dir + "/session.addr_stack", "w") as f:
        for a in disasm_viewer.addr_stack:
            if isinstance(a, tuple):
                a = a[0]
            f.write("%08x\n" % a)
        f.write("%08x\n" % disasm_viewer.cur_addr())


def load_addr_stack(project_dir):
    stack = []
    with open(project_dir + "/session.addr_stack") as f:
        for l in f:
            stack.append(int(l, 16))
    return stack
