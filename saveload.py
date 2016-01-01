import sys
import os

import engine


def save_exists(project_dir):
    return os.path.exists(project_dir + "/project.aspace")


def ensure_project_dir(project_dir):
    if not os.path.isdir(project_dir):
        os.makedirs(project_dir)


def save_state(project_dir):
    ensure_project_dir(project_dir)
    files = ["project.aspace", "project.aprops"]
    for fname in files:
        if os.path.exists(project_dir + "/" + fname):
            os.rename(project_dir + "/" + fname, project_dir + "/" + fname + ".bak")

    with open(project_dir + "/project.aspace", "w") as f:
        engine.ADDRESS_SPACE.save_areas(f)
    with open(project_dir + "/project.aprops", "w") as f:
        engine.ADDRESS_SPACE.save_addr_props(f)


def load_state(project_dir):
    if not os.path.exists(project_dir + "/project.aprops"):
        print("""
Cannot find project.aprops file. Possibly, you use old database format.
Use version 0.9 to migrate.
""")
        sys.exit(1)

    print("Loading state...")
    with open(project_dir + "/project.aspace", "r") as f:
        engine.ADDRESS_SPACE.load_areas(f)
    with open(project_dir + "/project.aprops", "r") as f:
        engine.ADDRESS_SPACE.load_addr_props(f)


# Save user-specific session parameter, like current address,
# address goto stack.
def save_session(project_dir, disasm_viewer):
    ensure_project_dir(project_dir)
    with open(project_dir + "/session.addr_stack", "w") as f:
        for a in disasm_viewer.addr_stack:
            f.write("%08x\n" % a)
        f.write("%08x\n" % disasm_viewer.cur_addr())
