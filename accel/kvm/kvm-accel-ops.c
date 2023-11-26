/*
 * QEMU KVM support
 *
 * Copyright IBM, Corp. 2008
 *           Red Hat, Inc. 2008
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *  Glauber Costa     <gcosta@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/main-loop.h"
#include "sysemu/kvm_int.h"
#include "sysemu/runstate.h"
#include "sysemu/cpus.h"
#include "qemu/guest-random.h"
#include "qapi/error.h"
#include "exec/gdbstub.h"
#include "migration/ram.h"
#include "qemu/log.h"

#include "kvm-cpus.h"
#include "sysemu/kernel-rr.h"

// target_ulong syscall_addr = 0xffffffff81200000;
// target_ulong pf_excep_addr = 0xffffffff8111e369;
// target_ulong copy_from_iter_addr = 0xffffffff810afc14;
// target_ulong copy_from_user_addr = 0xffffffff810b4fb8; 
// target_ulong copy_page_from_iter_addr = 0xffffffff810b0b16;
// target_ulong strncpy_addr = 0xffffffff810cbd51; // call   0xffffffff811183e0 <copy_user_enhanced_fast_string>
// target_ulong get_user_addr = 0xffffffff81118850;
// target_ulong strnlen_user_addr = 0xffffffff810cbe4a;
// target_ulong random_bytes_addr = 0xffffffff810e1e25;
// target_ulong last_removed_addr = 0;


const unsigned long syscall_addr = 0xffffffff81800000; // info addr entry_SYSCALL_64
const unsigned long pf_excep_addr = 0xffffffff81741960; // info addr exc_page_fault
const unsigned long copy_from_iter_addr = 0xffffffff8144af0d; // lib/iov_iter.c:186
const unsigned long copy_from_user_addr = 0xffffffff814528e7; // lib/usercopy.c:21
const unsigned long copy_page_from_iter_addr = 0xffffffff8144dd7e;
const unsigned long strncpy_addr = 0xffffffff81483732; // lib/strncpy_from_user.c:141
const unsigned long get_user_addr = 0xffffffff816c2220; // arch/x86/lib/getuser.S:103
const unsigned long strnlen_user_addr = 0xffffffff8146bb66; // lib/strnlen_user.c:115

// const unsigned long random_bytes_addr_start = 0xffffffff81533620; // b _get_random_bytes
// const unsigned long random_bytes_addr_end = 0xffffffff815337c0; // b drivers/char/random.c:382

const unsigned long random_bytes_addr_start = 0xffffffff81533660; // b _get_random_bytes
const unsigned long random_bytes_addr_end = 0xffffffff81533800; // b drivers/char/random.c:382

const unsigned long uaccess_begin = 0xffffffff811e084c;

unsigned long last_removed_addr = 0;

target_ulong userspace_start = 0x0000000000000000;
target_ulong userspace_end = 0x00007fffffffffff;

static bool singlestep_started = false;
static target_ulong singlestep_start = 0xffffffff810296c6;
static target_ulong singlestep_end = 0xffffffff810296c6; 
int count_num = 3;

// static int syscall_seq = 0;

static void rr_insert_userspace_int(CPUState *cs);

static bool rr_is_address_interceptible(target_ulong bp_addr)
{
    if (bp_addr != SYSCALL_ENTRY && bp_addr != pf_excep_addr && \
        bp_addr != copy_from_iter_addr && bp_addr != copy_from_user_addr && \
        bp_addr != strncpy_addr && \
        bp_addr != get_user_addr && \
        bp_addr != strnlen_user_addr && \
        bp_addr != random_bytes_addr_start && \
        bp_addr != random_bytes_addr_end && \
        bp_addr != copy_page_from_iter_addr && \
        bp_addr != uaccess_begin && \
        bp_addr != SYSCALL_EXIT && \
        bp_addr != PF_ASM_EXC && \
        bp_addr != PF_EXEC_END && \
        bp_addr != STRNCPY_FROM_USER && \
        bp_addr != STRNLEN_USER && \
        bp_addr != RR_RECORD_GFU && \
        bp_addr != RR_RECORD_CFU && \
        bp_addr != IRQ_ENTRY && \
        bp_addr != IRQ_EXIT && \
        bp_addr != singlestep_start && \
        bp_addr != singlestep_end)
        return false;

    return true;
}

static bool rr_is_address_sw(target_ulong bp_addr)
{
    if (bp_addr == strncpy_addr \
        || bp_addr == get_user_addr \
        || bp_addr == random_bytes_addr_start \
        || bp_addr == random_bytes_addr_end \
        || bp_addr == copy_from_iter_addr \
        || bp_addr == RR_RECORD_CFU \
        || bp_addr == RR_RECORD_GFU \
        || bp_addr == IRQ_ENTRY \
        || bp_addr == IRQ_EXIT)
    {
        return true;
    }

    return false;
}


void rr_insert_breakpoints(void)
{
    __attribute_maybe_unused__ int bp_ret ;
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        // bp_ret = kvm_insert_breakpoint(cpu, singlestep_start, 1, GDB_BREAKPOINT_HW);
        // if (bp_ret > 0) {
        //     printf("failed to insert bp for syscall: %d\n", bp_ret);
        // } else {
        //     printf("Inserted breakpoints for system call\n");
        // }

        // bp_ret = kvm_insert_breakpoint(cpu, singlestep_end, 1, GDB_BREAKPOINT_HW);
        // if (bp_ret > 0) {
        //     printf("failed to insert bp for syscall: %d\n", bp_ret);
        // } else {
        //     printf("Inserted breakpoints for system call\n");
        // }

        bp_ret = kvm_insert_breakpoint(cpu, SYSCALL_ENTRY, 1, GDB_BREAKPOINT_HW);
        if (bp_ret > 0) {
            printf("failed to insert bp for syscall: %d\n", bp_ret);
        } else {
            printf("Inserted breakpoints for system call\n");
        }

        bp_ret = kvm_insert_breakpoint(cpu, SYSCALL_EXIT, 1, GDB_BREAKPOINT_HW);
        if (bp_ret > 0) {
            printf("failed to insert bp for pf: %d\n", bp_ret);
        } else {
            printf("Inserted breakpoints for syscall exit\n");
        }

        bp_ret = kvm_insert_breakpoint(cpu, PF_ASM_EXC, 1, GDB_BREAKPOINT_HW);
        if (bp_ret > 0) {
            printf("failed to insert bp for pf: %d\n", bp_ret);
        } else {
            printf("Inserted breakpoints for pf\n");
        }

        bp_ret = kvm_insert_breakpoint(cpu, PF_EXEC_END, 1, GDB_BREAKPOINT_HW);
        if (bp_ret > 0) {
            printf("failed to insert bp for pf end: %d\n", bp_ret);
        } else {
            printf("Inserted breakpoints for pf end\n");
        }

        bp_ret = kvm_insert_breakpoint(cpu, RR_RECORD_CFU, 1, GDB_BREAKPOINT_SW);
        if (bp_ret > 0) {
            printf("failed to insert bp for cfu: %d\n", bp_ret);
        } else {
            printf("Inserted breakpoints for cfu\n");
        }

        bp_ret = kvm_insert_breakpoint(cpu, IRQ_ENTRY, 1, GDB_BREAKPOINT_SW);
        if (bp_ret > 0) {
            printf("failed to insert bp for irq entry: %d\n", bp_ret);
        } else {
            printf("Inserted breakpoints for irq entry\n");
        }

        bp_ret = kvm_insert_breakpoint(cpu, IRQ_EXIT, 1, GDB_BREAKPOINT_SW);
        if (bp_ret > 0) {
            printf("failed to insert bp for irq exit: %d\n", bp_ret);
        } else {
            printf("Inserted breakpoints for irq exit\n");
        }
    }
}

void rr_remove_breakpoints(void)
{
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        kvm_remove_breakpoint(cpu, singlestep_start, 1, GDB_BREAKPOINT_HW);
        kvm_remove_breakpoint(cpu, singlestep_end, 1, GDB_BREAKPOINT_HW);
        kvm_remove_breakpoint(cpu, SYSCALL_ENTRY, 1, GDB_BREAKPOINT_HW);
        kvm_remove_breakpoint(cpu, SYSCALL_EXIT, 1, GDB_BREAKPOINT_HW);
        // kvm_remove_breakpoint(cpu, copy_page_from_iter_addr, 1, GDB_BREAKPOINT_HW);
        // kvm_remove_breakpoint(cpu, copy_from_user_addr, 1, GDB_BREAKPOINT_HW);
        kvm_remove_breakpoint(cpu, RR_RECORD_CFU, 1, GDB_BREAKPOINT_SW);
        kvm_remove_breakpoint(cpu, IRQ_ENTRY, 1, GDB_BREAKPOINT_SW);
        kvm_remove_breakpoint(cpu, IRQ_EXIT, 1, GDB_BREAKPOINT_SW);
        kvm_remove_breakpoint(cpu, PF_ASM_EXC, 1, GDB_BREAKPOINT_HW);
        kvm_remove_breakpoint(cpu, PF_EXEC_END, 1, GDB_BREAKPOINT_HW);
        // kvm_remove_breakpoint(cpu, uaccess_begin, 1, GDB_BREAKPOINT_SW);
    }
}

__attribute_maybe_unused__ static void rr_insert_userspace_int(CPUState *cs)
{
    int bp_ret;

    target_ulong len = (userspace_end - userspace_start) / sizeof(uint8_t);

    bp_ret = kvm_insert_sw_breakpoint_no_save(cs, userspace_start, len);
    if (bp_ret > 0) {
        printf("failed to insert bp: %d\n", bp_ret);
        // break;
    } else {
        printf("inserted for user space\n");
    }

    return;
}


__attribute_maybe_unused__ static void handle_bp_points(CPUState *cpu, target_ulong bp_addr)
{
    if (!count_num)
        return;

    rr_handle_kernel_entry(cpu, bp_addr, rr_get_inst_cnt(cpu));

    if (bp_addr == singlestep_start) {
        if (!singlestep_started) {
            singlestep_started = true;
            // kvm_remove_breakpoint(cpu, bp_addr, 1, GDB_BREAKPOINT_HW);
            // last_removed_addr = bp_addr;
            // printf("singlestep started\n");
        } else {
            singlestep_started = false;
            count_num--;

            if (!count_num)
                last_removed_addr = 0;
        }

    }
}

static void handle_singlestep(CPUState *cpu, target_ulong bp_addr)
{
    if (bp_addr == singlestep_end) {
        count_num--;
        if (!count_num)
            last_removed_addr = 0;
    }

    rr_handle_kernel_entry(cpu, bp_addr, rr_get_inst_cnt(cpu));
}

__attribute_maybe_unused__ static bool handle_on_bp(CPUState *cpu)
{
    int bp_type;
    target_ulong bp_addr;

    bp_addr = cpu->kvm_run->debug.arch.pc;

    if (!rr_in_record())
        return false;

    if (!rr_is_address_interceptible(bp_addr))
        return false;

    if (cpu->singlestep_enabled != 0) {
        if (singlestep_started & count_num) {
            handle_singlestep(cpu, bp_addr);
            return true;
        }

        if (last_removed_addr == 0) {
            return false;
        }

        bp_type = GDB_BREAKPOINT_HW;

        if (rr_is_address_sw(last_removed_addr)) {
            bp_type = GDB_BREAKPOINT_SW;
        }

        if (last_removed_addr > 0) {
            if (kvm_insert_breakpoint(cpu, last_removed_addr, 1, bp_type) > 0) {
                printf("failed to insert bp\n");
                abort();
            }
        }

        // handle_bp_points(cpu, bp_addr);

        cpu_single_step(cpu, 0);

        last_removed_addr = 0;
    } else {
        
        bp_type = GDB_BREAKPOINT_HW;

        if (!rr_is_address_interceptible(bp_addr)) {
            return false;
        }

        handle_bp_points(cpu, bp_addr);

        if (rr_is_address_sw(bp_addr)) {
            bp_type = GDB_BREAKPOINT_SW;
        }
        cpu_single_step(cpu, SSTEP_ENABLE | SSTEP_NOIRQ);
        if (kvm_remove_breakpoint(cpu, bp_addr, 1, bp_type) > 0) {
            printf("failed to remove bp\n");
            abort();
        }

        last_removed_addr = bp_addr;
    }

    return true;
}

static void *kvm_vcpu_thread_fn(void *arg)
{
    CPUState *cpu = arg;
    int r;

    rcu_register_thread();

    qemu_mutex_lock_iothread();
    qemu_thread_get_self(cpu->thread);
    cpu->thread_id = qemu_get_thread_id();
    cpu->can_do_io = 1;
    current_cpu = cpu;

    r = kvm_init_vcpu(cpu, &error_fatal);
    kvm_init_cpu_signals(cpu);

    /* signal CPU creation */
    cpu_thread_signal_created(cpu);
    qemu_guest_random_seed_thread_part2(cpu->random_seed);

    do {
        if (cpu_can_run(cpu)) {
            r = kvm_cpu_exec(cpu);
            if (r == EXCP_DEBUG) {
                if (!handle_on_bp(cpu)) {
                    // printf("break on addr 0x%llx\n", cpu->kvm_run->debug.arch.pc);
                    cpu_handle_guest_debug(cpu);
                }
            }
        }
        qemu_wait_io_event(cpu);
    } while (!cpu->unplug || cpu_can_run(cpu));

    kvm_destroy_vcpu(cpu);
    cpu_thread_signal_destroyed(cpu);
    qemu_mutex_unlock_iothread();
    rcu_unregister_thread();
    return NULL;
}

static void kvm_start_vcpu_thread(CPUState *cpu)
{
    char thread_name[VCPU_THREAD_NAME_SIZE];

    cpu->thread = g_malloc0(sizeof(QemuThread));
    cpu->halt_cond = g_malloc0(sizeof(QemuCond));
    qemu_cond_init(cpu->halt_cond);
    snprintf(thread_name, VCPU_THREAD_NAME_SIZE, "CPU %d/KVM",
             cpu->cpu_index);
    qemu_thread_create(cpu->thread, thread_name, kvm_vcpu_thread_fn,
                       cpu, QEMU_THREAD_JOINABLE);
}

static bool kvm_vcpu_thread_is_idle(CPUState *cpu)
{
    return !kvm_halt_in_kernel();
}

static bool kvm_cpus_are_resettable(void)
{
    return !kvm_enabled() || kvm_cpu_check_are_resettable();
}

static void kvm_accel_ops_class_init(ObjectClass *oc, void *data)
{
    AccelOpsClass *ops = ACCEL_OPS_CLASS(oc);

    ops->create_vcpu_thread = kvm_start_vcpu_thread;
    ops->cpu_thread_is_idle = kvm_vcpu_thread_is_idle;
    ops->cpus_are_resettable = kvm_cpus_are_resettable;
    ops->synchronize_post_reset = kvm_cpu_synchronize_post_reset;
    ops->synchronize_post_init = kvm_cpu_synchronize_post_init;
    ops->synchronize_state = kvm_cpu_synchronize_state;
    ops->synchronize_pre_loadvm = kvm_cpu_synchronize_pre_loadvm;
}

static const TypeInfo kvm_accel_ops_type = {
    .name = ACCEL_OPS_NAME("kvm"),

    .parent = TYPE_ACCEL_OPS,
    .class_init = kvm_accel_ops_class_init,
    .abstract = true,
};

static void kvm_accel_ops_register_types(void)
{
    type_register_static(&kvm_accel_ops_type);
}
type_init(kvm_accel_ops_register_types);
