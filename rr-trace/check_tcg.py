
def check_tcg_trace():
    inst_list = []

    with open("tcg-trace", "r") as rf:
        inst_num = 0
        cur_addr = None
        pre_exec_num = 0
        post_exec_num = 0
        ended = None
        

        bad_addr = set()

        for l in rf.readlines():
            if l.startswith("Reduced inst cnt"):
                items = l.split(",")
                pre_exec_num = int(items[0].split()[3])
                if ended is not None and not ended:
                    print("Last bad addr")

                ended = False
    
            elif l.startswith("end execute tb"):
                items = l.split(",")
                post_exec_num = int(items[1].split()[2])
                if post_exec_num <= pre_exec_num:
                    # print("Bad addr: {}".format(cur_addr))
                    bad_addr.add(cur_addr)
                
                ended = True
            elif l.startswith("0xf"):
                cur_addr = l.split(":")[0]

    print(bad_addr)

    return

check_tcg_trace()
