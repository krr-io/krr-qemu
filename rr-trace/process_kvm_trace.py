import count_inst
import common

def parse_kvm_trace(dedup=False):
    inst_list = []

    with open("kvm-trace", "r") as rf:
        for l in rf.readlines():
            if l.startswith("=>"):
                addr = l.split()[1]
                inst_list.append(addr)

    if dedup:
        final_inst_list = count_inst.dedup(inst_list)
    else:
        final_inst_list = inst_list

    common.write_inst_list(final_inst_list, "trace-addr/kvm-trace-addr")

    return

parse_kvm_trace(dedup=True)
