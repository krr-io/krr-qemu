
def analyze_kvm():
    last_inst = None
    inst_num = 0

    with open("kvm-trace-addr", "r") as kvm_file:
        with open("kvm-trace-addr-nodup", "a") as kvm_file_r:
            kvm_insts = kvm_file.readlines()

            for inst in kvm_insts:
                cur_inst = inst.strip()
                if last_inst is None or last_inst != cur_inst:
                    inst_num += 1
                    last_inst = cur_inst
                    kvm_file_r.write(inst)

    return inst_num


def dedup(inst_list):
    last_inst = None
    inst_num = 0
    deduped_inst = []

    for inst in inst_list:
        cur_inst = inst
        if last_inst is None or last_inst != cur_inst:
            inst_num += 1
            last_inst = cur_inst
            deduped_inst.append(cur_inst)

    return deduped_inst


def compare():
    with open("kvm-trace-addr-nodup", "r") as kvm_file:
        kvm_insts = kvm_file.readlines()

        with open("tcg-trace-nodup", "r") as tcg_file:
            tcg_insts = tcg_file.readlines()

            for i, kvm_inst in enumerate(kvm_insts):
                kvm_inst_s = kvm_inst.strip()
                tcg_inst_s = tcg_insts[i].strip()
                if kvm_inst_s != tcg_inst_s:
                    print("Inconsistent kvm inst({}) != tcg inst({})".format(kvm_inst_s, tcg_inst_s))
                    exit(1)
