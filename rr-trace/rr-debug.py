import gdb

pte_count = 0

DEBUG_POINT1 = "sysvec_apic_timer_interrupt"

step = False

record_regs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]

long_type = gdb.lookup_type("unsigned long")

def unsigned(val):
    return val + (1 << 32)

def inspect():
    with open("kvm-trace", 'a') as f:
        while 1:
            # global step
            # if gdb.selected_frame().pc() == 18446744071580017059:
            #     print("started recording")
            #     step = True

            # if step:
            out = gdb.execute('x/i $pc', to_string=True)
            regs = []

            for r in record_regs:
                reg_val_raw = gdb.parse_and_eval("${}".format(r)).cast(long_type)
                # reg_val = int(reg_val_raw) & 0xffffffffffffffff
                reg_val = hex(reg_val_raw)
                regs.append(
                    r + "=" + str(reg_val)
                )
                # gdb.execute("p/x ${}".format(r))

            f.write("Regs: {}\n".format(",".join(regs)))
            f.write(out)

            gdb.execute("stepi")

class DebugPrintingBreakpoint(gdb.Breakpoint):
    debugging_IDs = frozenset({37, 153, 420})
    pte_count = 0
    syscall_cnt = 0

    def stop(self):
        with open("kvm-trace", 'a') as f:
            f.write("Hit sysvec_apic_timer_interrupt")
        return False 


# DebugPrintingBreakpoint(DEBUG_POINT1)

# gdb.execute("continue")
inspect()
