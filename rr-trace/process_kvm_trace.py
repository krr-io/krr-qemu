import count_inst
import common

def parse_kvm_trace(dedup=False):
    inst_list = []
    regs_list = []

    with open("kvm-trace", "r") as rf:
        for l in rf.readlines():
            if l.startswith("=>"):
                addr = l.split()[1]
                inst_list.append(addr)
            elif l.startswith("Regs: "):
                regs_list.append(l.strip())

    if dedup:
        final_inst_list = count_inst.dedup(inst_list)
    else:
        final_inst_list = inst_list

    # common.write_inst_list(final_inst_list, "trace-addr/kvm-trace-addr")
    common.write_inst_regs_list(final_inst_list, regs_list, "trace-addr/kvm-trace-addr-regs")

    return

parse_kvm_trace(dedup=False)
