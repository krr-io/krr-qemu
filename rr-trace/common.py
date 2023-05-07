import os


def write_inst_list(inst_list, filename):
    if os.path.exists(filename):
        os.remove(filename)

    with open(filename, "a") as wf:
        for inst in inst_list:
            wf.write(inst + "\n")
