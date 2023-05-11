import count_inst
import common

def parse_tcg_trace(dedup=False):
    inst_list = []
    regs_list = []

    with open("tcg-trace", "r") as rf:
        in_block = False

        for l in rf.readlines():
            if l.startswith("Execute TB"):
                in_block = False


            if l.startswith("0xf"):
                if not in_block:
                    inst_list.append(l.split()[0][:-1])
                    in_block = True
            
            if l.startswith("Regs: "):
                regs_list.append(l.strip())

    if dedup:
        final_inst_list = count_inst.dedup(inst_list)
    else:
        final_inst_list = inst_list

    # common.write_inst_list(final_inst_list, "trace-addr/tcg-trace-addr")
    common.write_inst_regs_list(final_inst_list, regs_list, "trace-addr/tcg-trace-addr-regs")


    return

parse_tcg_trace(dedup=False)
