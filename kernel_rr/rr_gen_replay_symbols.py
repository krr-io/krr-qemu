import gdb
import copy


KERNEL_RR_HEADER = "/home/projects/qemu-tcg-kvm/include/sysemu/kernel-rr.h"
VERSION = str(gdb.parse_and_eval("init_uts_ns.name"))


def filter_info_addr(symbol):
    output = gdb.execute("info addr {}".format(symbol), to_string=True)
    blocks = output.split()

    for block in blocks:
        if block.startswith("0xf"):
            if block.endswith("."):
                return block[:-1]
            
            return block

    raise Exception("Invalid debug output")

def filter_loc_addr(loc):
    output = gdb.execute("b {}".format(loc), to_string=True)
    lines = output.split("\n")
    for line in lines:
        if line.startswith("Breakpoint"):
            output = line

    blocks = output.split()

    candidate = blocks[3][:-1]

    try:
        int(candidate, 16)
        return candidate
    except:
        return "0"


def fetch_rr_gfu_begin():
    return filter_info_addr("rr_gfu_begin")

def fetch_strncpy_from_user():
    return filter_info_addr("strncpy_from_user")

def fetch_strnlen_user():
    return filter_info_addr("strnlen_user")

def fetch_random_gen():
    return filter_info_addr("rr_record_random")

def fetch_exc_page_fault():
    return filter_info_addr("exc_page_fault")

def fetch_exc_page_fault_end():
    if "6.1.0" in VERSION or "6.1.18" in VERSION or "6.1.31" in VERSION or "6.1.34" in VERSION or "6.1.35" in VERSION:
        return filter_loc_addr("fault.c:1580")
    elif "6.1.86" in VERSION or "6.1.84" in VERSION:
        return filter_loc_addr("fault.c:1523")
    elif "6.1.61" in VERSION or "6.1.77" in VERSION or "6.1.38" in VERSION or "6.1.62" in VERSION or "6.1.66" in VERSION:
        return filter_loc_addr("fault.c:1532")
    elif "5.17.4" in VERSION:
        return filter_loc_addr("fault.c:1545")
    else:
        return filter_loc_addr("fault.c:1463")

def fetch_rr_record_cfu():
    return filter_info_addr("rr_record_cfu")

def fetch_rr_cfu_begin():
    return filter_info_addr("rr_cfu_begin")

def fetch_gfu_nocheck1():
    return filter_loc_addr("getuser.S:127")

def fetch_rr_record_gfu():
    return filter_loc_addr("getuser.S:103")

def fetch_gfu_nocheck4():
    return filter_loc_addr("getuser.S:147")

def fetch_gfu_nocheck8():
    return filter_loc_addr("getuser.S:162")

def fetch_syscall_entry():
    return filter_info_addr("entry_SYSCALL_64")

def fetch_syscall_exit():
    return filter_info_addr("syscall_exit_to_user_mode")

def fetch_pf_asm_exec():
    return filter_info_addr("asm_exc_page_fault")

def fetch_irq_entry():
    return filter_info_addr("irqentry_enter")

def fetch_irq_exit():
    return filter_info_addr("irqentry_exit")

def fetch_gfu4():
    return filter_loc_addr("getuser.S:88")

def fetch_record_syscall():
    return filter_loc_addr("rr_record_syscall")

def fetch_handle_syscall():
    return filter_info_addr("rr_handle_syscall")

def fetch_release():
    return filter_loc_addr("arch/x86/kernel/rr_serialize.c:116")

def fetch_rr_record_pte_clear():
    return filter_info_addr("rr_record_pte_clear")

def fetch_rr_read_pte():
    return filter_info_addr("rr_read_pte")

def fetch_rr_iret():
    return filter_loc_addr("entry_64.S:702")

def fetch_rr_sysret():
    return filter_loc_addr("entry_64.S:226")

def fetch_rr_read_pte_once():
    return filter_info_addr("rr_read_pte_once")

handlers = {
    "STRNCPY_FROM_USER": fetch_strncpy_from_user,
    "STRNLEN_USER": fetch_strnlen_user,
    "RANDOM_GEN": fetch_random_gen,
    "PF_EXEC": fetch_exc_page_fault,
    "PF_EXEC_END": fetch_exc_page_fault_end,
    "RR_RECORD_CFU": fetch_rr_record_cfu,
    "RR_CFU_BEGIN": fetch_rr_cfu_begin,
    "RR_RECORD_GFU": fetch_rr_record_gfu,
    "RR_GFU4": fetch_gfu4,
    "RR_GFU_NOCHECK1": fetch_gfu_nocheck1,
    "RR_GFU_NOCHECK4": fetch_gfu_nocheck4,
    "RR_GFU_NOCHECK8": fetch_gfu_nocheck8,
    "SYSCALL_ENTRY": fetch_syscall_entry,
    "SYSCALL_EXIT": fetch_syscall_exit,
    "PF_ASM_EXC": fetch_pf_asm_exec,
    "IRQ_ENTRY": fetch_irq_entry,
    "IRQ_EXIT": fetch_irq_exit,
    "RR_RECORD_SYSCALL": fetch_record_syscall,
    "RR_HANDLE_SYSCALL": fetch_handle_syscall,
    "LOCK_RELEASE": fetch_release,
    "RR_GFU_BEGIN": fetch_rr_gfu_begin,
    "RR_PTE_CLEAR": fetch_rr_record_pte_clear,
    "RR_PTE_READ": fetch_rr_read_pte,
    "RR_IRET": fetch_rr_iret,
    "RR_SYSRET": fetch_rr_sysret,
    "RR_PTE_READ_ONCE": fetch_rr_read_pte_once,
}


def generate_symbols():
    generate_done = False
    print(VERSION)

    with open(KERNEL_RR_HEADER, 'r') as file:
        lines = file.readlines()
        output_lines = copy.deepcopy(lines)

        for index, line in enumerate(lines):
            spots = line.split()

            if line.startswith("#define"):
                macro = spots[1]

                if macro in handlers:
                    try:
                        spots[2] = handlers[macro]()
                    except Exception as e:
                        print("Failed to generate symbol for {}: {}".format(macro, e))
                    else:
                        print("Writing symbol addr {} for macro {}".format(spots[2], macro))
                        output_lines[index] = ' '.join(spots) + '\n'

        generate_done = True

    if generate_done:
        with open(KERNEL_RR_HEADER, 'w') as file:
            file.write(''.join(output_lines))


if __name__ == "__main__":
    generate_symbols()
