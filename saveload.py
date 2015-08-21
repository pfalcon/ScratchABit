import os

import engine


def save_exists(project_dir):
    return os.path.exists(project_dir + "/project.aspace")


def save_state(project_dir):
    if not os.path.isdir(project_dir):
        os.makedirs(project_dir)
    files = ["project.labels", "project.comments", "project.args",
             "project.xrefs", "project.funcs", "project.aspace"]
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
    with open(project_dir + "/project.funcs", "w") as f:
        engine.ADDRESS_SPACE.save_funcs(f)
    with open(project_dir + "/project.aspace", "w") as f:
        engine.ADDRESS_SPACE.save_areas(f)
    with open(project_dir + "/project.yaml-ref", "w") as f:
        engine.ADDRESS_SPACE.save_ref_yaml(f)
    with open(project_dir + "/project.aprops", "w") as f:
        engine.ADDRESS_SPACE.save_addr_props(f)


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
    with open(project_dir + "/project.funcs", "r") as f:
        engine.ADDRESS_SPACE.load_funcs(f)
    with open(project_dir + "/project.aspace", "r") as f:
        engine.ADDRESS_SPACE.load_areas(f)
    with open(project_dir + "/project.aprops", "r") as f:
        engine.ADDRESS_SPACE.load_addr_props(f)
