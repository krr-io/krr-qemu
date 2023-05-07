def gen_reg_pair(reg_pair):
    reg, val = reg_pair.split("=")[0], reg_pair.split("=")[1]
    new_val = hex(int(val) & (2**64-1))

    return "{}={}".format(reg, new_val)


def process_kvm_trace():
    with open("kvm-trace", "r") as rf:
        with open("kvm-trace-new", "a") as wf:
            for l in rf.readlines():
                if l.startswith("Reg"):
                    s = "Regs: "

                    for reg_pair in l.split()[1].split(","):
                        s += gen_reg_pair(reg_pair)
                        s += ","
                    wf.write(s)
                    wf.write("\n")
                else:
                    wf.write(l)


def parse_kvm_trace():
    with open("kvm-trace-new", "r") as rf:
        with open("kvm-trace-addr", "w") as wf:
            for l in rf.readlines():
                if l.startswith("Reg"):
                    s = "Regs: "

                    for reg_pair in l.split()[1].split(","):
                        s += gen_reg_pair(reg_pair)

                    wf.write(l)
                    continue
                else:
                    wf.write(l.split()[1])
                    wf.write("\n")
    return

def parse_tcg_trace():
    with open("tcg-trace-addr", "r") as rf:
        with open("tcg-trace-addr-out", "a") as wf:
            for l in rf.readlines():
                if l.startswith("Reg"):
                    continue
                elif l.startswith("0xf"):
                    wf.write(l.split()[0][:-1])
                    wf.write("\n")


# process_kvm_trace()
# parse_kvm_trace()
parse_tcg_trace()

