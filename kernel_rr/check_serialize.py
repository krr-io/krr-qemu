
with open("/home/projects/qemu-tcg-kvm/build/rec.log") as f:
    lines = f.readlines()

    pre_line_cpu_id = None
    is_pre_release = True

    for line in lines:
        if "cpu_id" not in line:
            continue

        if "GFU" in line or "CFU" in line or "Strnlen" in line:
            continue
        
        items = line.split(",")

        cpu_id_index = -2

        if "Interrupt" in line or "Syscall" in line or "exception" in line:
            cpu_id_index = -3

        if "Lock Released" in line:
            cpu_id_index = -1
            cpu_id_item = items[cpu_id_index]
            is_pre_release = True
            pre_line_cpu_id = cpu_id_item.split("=")[1]
            continue
        else:
            cpu_id_item = items[cpu_id_index]
            my_cpu_id = cpu_id_item.split("=")[1]


        if my_cpu_id != pre_line_cpu_id and not is_pre_release:
            print("Line '{}' has problem, my_cpu_id={} pre_cpu={}".format(line, my_cpu_id, pre_line_cpu_id))
            break

        pre_line_cpu_id = my_cpu_id
        is_pre_release = False