import os
import sys

import gdb
import copy


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

def fetch_exc_general_protectiont():
    return filter_info_addr("exc_general_protection")

def find_last_return_address(function_name):
    """
    Find the address of the last return instruction in a function.
    
    Args:
        function_name: The name of the function to analyze
        
    Returns:
        The address of the last return instruction as an integer, or None if not found
    """
    try:
        # Disassemble the function
        disassembly = gdb.execute(f"disassemble {function_name}", to_string=True)
        lines = disassembly.splitlines()
        
        # Find all ret instructions and __x86_return_thunk calls
        ret_instructions = []
        for line in lines:
            line = line.strip()
            if ("ret" in line.split() and "<+" in line) or "__x86_return_thunk" in line:
                addr_str = line.split()[0]
                # Handle both regular ret instructions and __x86_return_thunk calls
                if "<+" in line:
                    offset = int(line.split("<+")[1].split(">")[0])
                else:
                    # For __x86_return_thunk calls, get the offset from its position in the function
                    # Assuming the line number in disassembly roughly corresponds to offset
                    offset = lines.index(line)
                
                ret_addr = int(addr_str, 16)
                ret_instructions.append((ret_addr, offset))
        
        if not ret_instructions:
            return None
        
        # Sort by offset to find the last one
        ret_instructions.sort(key=lambda x: x[1])
        last_ret_addr = ret_instructions[-1][0]
        
        return last_ret_addr
        
    except gdb.error:
        return None

def fetch_exc_page_fault_end():
    try:
        # Execute the disassemble command for exc_page_fault
        disasm_output = gdb.execute("disassemble exc_page_fault", to_string=True)

        # Split the output into lines
        lines = disasm_output.strip().split('\n')

        # Search for the line containing irqentry_exit
        for line in lines:
            if 'irqentry_exit' in line:
                # Extract the address using string operations
                # Line format: 0xffffffff89204dec <+124>:	jmp    0xffffffff89205770 <irqentry_exit>

                # Find the first 0x which should be the instruction address
                start_idx = line.find('0x')
                if start_idx == -1:
                    continue

                # Find the end of the hex address (before the space and <)
                end_idx = line.find(' ', start_idx)
                if end_idx == -1:
                    continue

                address = line[start_idx:end_idx]
                print("Found irqentry_exit call at address: " + address)
                return address

        print("irqentry_exit not found in exc_page_fault disassembly")
        return None

    except:
        print("Error occurred while searching for irqentry_exit")
        return None

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
    return filter_loc_addr("arch/x86/kernel/rr_serialize.c:147")

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

def fetch_rr_page_map():
    return filter_info_addr("rr_record_page_map")

def fetch_rr_begin_record_io_uring():
    return filter_info_addr("rr_begin_record_io_uring")

def fetch_rr_record_io_uring_entry():
    return filter_info_addr("rr_record_io_uring_entry")

def fetch_acquire_result():
    addr = find_last_return_address("rr_do_acquire_smp_exec")
    if not addr:
        raise Exception("Failed to analyze symbol of rr_do_acquire_smp_exec")

    return hex(addr)


handlers = {
    "STRNCPY_FROM_USER": fetch_strncpy_from_user,
    "STRNLEN_USER": fetch_strnlen_user,
    "PF_EXEC": fetch_exc_page_fault,
    "PF_EXEC_END": fetch_exc_page_fault_end,
    # "RR_RECORD_CFU": fetch_rr_record_cfu,
    "GP_EXEC": fetch_exc_general_protectiont,
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
    "RR_PAGE_MAP": fetch_rr_page_map,
    "RR_IO_URING_BEGIN": fetch_rr_begin_record_io_uring,
    "RR_IO_URING_RECORD_ENTRY": fetch_rr_record_io_uring_entry,
    "RR_LOCK_ACQUIRE_RET": fetch_acquire_result,
}


def generate_symbols(kernel_rr_header):
    generate_done = False
    print(VERSION)

    with open(kernel_rr_header, 'r') as file:
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
                        raise
                    else:
                        print("Writing symbol addr {} for macro {}".format(spots[2], macro))
                        output_lines[index] = ' '.join(spots) + '\n'

        generate_done = True

    print("Symbol generation finished, please recompile the KRR QEMU")
    if generate_done:
        with open(kernel_rr_header, 'w') as file:
            file.write(''.join(output_lines))


if __name__ == "__main__":
    qemu_path = sys.argv[0]
    generate_symbols(os.path.join(qemu_path, "include/sysemu/kernel-rr.h"))
