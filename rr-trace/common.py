import os


def write_inst_list(inst_list, filename):
    if os.path.exists(filename):
        os.remove(filename)

    with open(filename, "a") as wf:
        for inst in inst_list:
            wf.write(inst + "\n")

def write_inst_regs_list(inst_list, regs_list, filename):
    if os.path.exists(filename):
        os.remove(filename)

    with open(filename, "a") as wf:
        for index, inst in enumerate(inst_list):
            wf.write(regs_list[index] + "\n" + inst + "\n")
