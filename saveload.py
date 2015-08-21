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


def migrate_to_yaml(project_dir):
    print("Migrating saved state to YAML-based format...")
    with open(project_dir + "/project.aspace", "r") as f:
        engine.ADDRESS_SPACE.load_areas(f)
    with open(project_dir + "/project.labels", "r") as f:
        engine.ADDRESS_SPACE.load_labels(f)
    with open(project_dir + "/project.comments", "r") as f:
        engine.ADDRESS_SPACE.load_comments(f)
    with open(project_dir + "/project.args", "r") as f:
        engine.ADDRESS_SPACE.load_arg_props(f)
    with open(project_dir + "/project.xrefs", "r") as f:
        engine.ADDRESS_SPACE.load_xrefs(f)
    with open(project_dir + "/project.funcs", "r") as f:
        engine.ADDRESS_SPACE.load_funcs(f)

    with open(project_dir + "/project.aprops", "w") as f:
        engine.ADDRESS_SPACE.save_ref_yaml(f)

    if not os.path.isdir(project_dir + "/old"):
        os.makedirs(project_dir + "/old")
    files = ["project.labels", "project.comments", "project.args",
             "project.xrefs", "project.funcs"]
    for fname in files:
        os.rename(project_dir + "/" + fname, project_dir + "/old/" + fname)
    print("Migration complete. Restart to use new saved state format.")
    sys.exit(100)


def load_state(project_dir):
    if not os.path.exists(project_dir + "/project.aprops"):
        migrate_to_yaml(project_dir)

    print("Loading state...")
    with open(project_dir + "/project.aspace", "r") as f:
        engine.ADDRESS_SPACE.load_areas(f)
    with open(project_dir + "/project.aprops", "r") as f:
        engine.ADDRESS_SPACE.load_addr_props(f)
