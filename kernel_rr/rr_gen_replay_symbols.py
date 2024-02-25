import gdb
import copy


KERNEL_RR_HEADER = "/home/projects/qemu-tcg-kvm/include/sysemu/kernel-rr.h"


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
    blocks = output.split()

    return blocks[3][:-1]


def fetch_strncpy_from_user():
    return filter_info_addr("strncpy_from_user")

def fetch_strnlen_user():
    return filter_loc_addr("lib/strnlen_user.c:116")

def fetch_random_gen():
    return filter_info_addr("rr_record_random")

def fetch_exc_page_fault():
    return filter_info_addr("exc_page_fault")

def fetch_exc_page_fault_end():
    return filter_loc_addr("fault.c:1580")

def fetch_rr_record_cfu():
    return filter_info_addr("rr_record_cfu")

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


handlers = {
    "STRNCPY_FROM_USER": fetch_strncpy_from_user,
    "STRNLEN_USER": fetch_strnlen_user,
    "RANDOM_GEN": fetch_random_gen,
    "PF_EXEC": fetch_exc_page_fault,
    "PF_EXEC_END": fetch_exc_page_fault_end,
    "RR_RECORD_CFU": fetch_rr_record_cfu,
    "RR_RECORD_GFU": fetch_rr_record_gfu,
    "RR_GFU_NOCHECK4": fetch_gfu_nocheck4,
    "RR_GFU_NOCHECK8": fetch_gfu_nocheck8,
    "SYSCALL_ENTRY": fetch_syscall_entry,
    "SYSCALL_EXIT": fetch_syscall_exit,
    "PF_ASM_EXC": fetch_pf_asm_exec,
    "IRQ_ENTRY": fetch_irq_entry,
    "IRQ_EXIT": fetch_irq_exit,
    "RR_GFU4": fetch_gfu4,
}


def generate_symbols():
    generate_done = False

    with open(KERNEL_RR_HEADER, 'r') as file:
        lines = file.readlines()
        output_lines = copy.deepcopy(lines)

        for index, line in enumerate(lines):
            spots = line.split()

            if line.startswith("#define"):
                macro = spots[1]

                if macro in handlers:
                    spots[2] = handlers[macro]()
                    print("Writing symbol addr {} for macro {}".format(spots[2], macro))
                    output_lines[index] = ' '.join(spots) + '\n'

        generate_done = True

    if generate_done:
        with open(KERNEL_RR_HEADER, 'w') as file:
            file.write(''.join(output_lines))


if __name__ == "__main__":
    generate_symbols()
