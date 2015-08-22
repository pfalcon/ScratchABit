import sys
import os

import engine


def save_exists(project_dir):
    return os.path.exists(project_dir + "/project.aspace")


def save_state(project_dir):
    if not os.path.isdir(project_dir):
        os.makedirs(project_dir)
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
