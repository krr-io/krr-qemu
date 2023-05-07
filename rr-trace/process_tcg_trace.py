import count_inst
import common

def parse_tcg_trace(dedup=False):
    inst_list = []

    with open("tcg-trace", "r") as rf:
        in_block = False

        for l in rf.readlines():
            if l.startswith("Execute TB"):
                in_block = False


            if l.startswith("0xf"):
                if not in_block:
                    inst_list.append(l.split()[0][:-1])
                    in_block = True

    if dedup:
        final_inst_list = count_inst.dedup(inst_list)
    else:
        final_inst_list = inst_list

    common.write_inst_list(final_inst_list, "trace-addr/tcg-trace-addr")

    return

parse_tcg_trace(dedup=True)
