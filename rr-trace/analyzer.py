

def analyze():
    with open("kvm-trace-addr-nodup") as kvm_file:
        kvm_insts = kvm_file.readlines()

        with open("tcg-trace") as tcg_file:
            cur_block = []
            init_inst_num = 0
            cur_inst_num = 0
            to_verify = False

            for line in tcg_file.readlines():
                if line.startswith("Execute TB:"):
                    cur_block = []
                    to_verify = True
                    print("New Block")
                
                elif line.startswith("0xf"):
                    if cur_inst_num < init_inst_num:
                        continue
                    rip = line.split()[0][:-1]
                    if to_verify:
                        expected = kvm_insts[cur_inst_num].strip()
                        if rip != expected:
                            print("Inconsistent instruction: Current({})!=Expected({}), executed inst: {}".format(rip, expected, cur_inst_num))
                            exit(1)
                        to_verify = False
                    cur_block.append(rip)

                elif line.startswith("end execute tb"):
                    # print(line.split(":")[1])
                    cur_inst_num = int(line.split()[4]) - init_inst_num

            print("All block passed")

if __name__ == "__main__":
    analyze()