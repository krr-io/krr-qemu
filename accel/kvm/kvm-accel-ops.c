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

#include "kvm-cpus.h"
#include "sysemu/kernel-rr.h"

target_ulong syscall_addr = 0xffffffff81200000;
target_ulong pf_excep_addr = 0xffffffff8111e369;
// target_ulong copy_from_iter_addr = 0xffffffff810afbf1; // call   <_copy_from_iter+97>
target_ulong copy_from_iter_addr = 0xffffffff810afc14;

// target_ulong copy_from_user_addr = 0xffffffff810b4f7d; // call   0xffffffff811183e0 <copy_user_enhanced_fast_string>
target_ulong copy_from_user_addr = 0xffffffff810b4fb8; 

target_ulong copy_page_from_iter_addr = 0xffffffff810b0b16;

target_ulong strncpy_addr = 0xffffffff810cbd51; // call   0xffffffff811183e0 <copy_user_enhanced_fast_string>

target_ulong get_user_addr = 0xffffffff81118850;
target_ulong strnlen_user_addr = 0xffffffff810cbe4a;
target_ulong random_bytes_addr = 0xffffffff810e1e25;

// target_ulong cfu_addr3 = 0xffffffff811183e3;

target_ulong last_removed_addr = 0;

target_ulong userspace_start = 0x0000000000000000;
target_ulong userspace_end = 0x00007fffffffffff;

// static int syscall_seq = 0;

static void rr_insert_userspace_int(CPUState *cs);

static bool rr_is_address_interceptible(target_ulong bp_addr)
{
    if (bp_addr != syscall_addr && bp_addr != pf_excep_addr && \
        bp_addr != copy_from_iter_addr && bp_addr != copy_from_user_addr && \
        bp_addr != strncpy_addr && \
        bp_addr != get_user_addr && \
        bp_addr != strnlen_user_addr && \
        bp_addr != random_bytes_addr && \
        bp_addr != copy_page_from_iter_addr)
        return false;

    return true;
}

static bool rr_is_address_sw(target_ulong bp_addr)
{
    if (bp_addr == strncpy_addr \
        || bp_addr == get_user_addr \
        || bp_addr == strnlen_user_addr \
        || bp_addr == random_bytes_addr \
        || bp_addr == copy_from_iter_addr)
    {
        return true;
    }

    return false;
}

__attribute_maybe_unused__ static void rr_handle_kernel_entry(CPUState *cpu, target_ulong bp_addr) {
    // char ss_name[10];
    if (bp_addr == syscall_addr) {
        sync_dirty_pages(cpu);
    }
}


void rr_insert_breakpoints(void)
{
    __attribute_maybe_unused__ int bp_ret;
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        bp_ret = kvm_insert_breakpoint(cpu, syscall_addr, 1, GDB_BREAKPOINT_HW);
        if (bp_ret > 0) {
            printf("failed to insert bp: %d\n", bp_ret);
        } else {
            printf("Inserted breakpoints\n");
        }

        bp_ret = kvm_insert_breakpoint(cpu, pf_excep_addr, 1, GDB_BREAKPOINT_HW);
        if (bp_ret > 0) {
            printf("failed to insert bp: %d\n", bp_ret);
        } else {
            printf("Inserted breakpoints\n");
        }

        bp_ret = kvm_insert_breakpoint(cpu, copy_page_from_iter_addr, 1, GDB_BREAKPOINT_HW);
        if (bp_ret > 0) {
            printf("failed to insert bp for copy_page_from_iter_addr: %d\n", bp_ret);
        } else {
            printf("Inserted breakpoints for copy_page_from_iter_addr\n");
        }

        bp_ret = kvm_insert_breakpoint(cpu, copy_from_user_addr, 1, GDB_BREAKPOINT_HW);
        if (bp_ret > 0) {
            printf("failed to insert bp for CFU[%lx]: %d\n", copy_from_user_addr, bp_ret);
        } else {
            printf("Inserted breakpoints\n");
        }

        bp_ret = kvm_insert_breakpoint(cpu, copy_from_iter_addr, 1, GDB_BREAKPOINT_SW);
        if (bp_ret > 0) {
            printf("failed to insert bp for CFU[%lx]: %d\n", copy_from_iter_addr, bp_ret);
        } else {
            printf("Inserted breakpoints\n");
        }

        bp_ret = kvm_insert_breakpoint(cpu, strncpy_addr, 1, GDB_BREAKPOINT_SW);
        if (bp_ret > 0) {
            printf("failed to insert bp for strncpy_addr: %d\n", bp_ret);
        } else {
            printf("Inserted breakpoints for strncpy_addr\n");
        }

        bp_ret = kvm_insert_breakpoint(cpu, get_user_addr, 1, GDB_BREAKPOINT_SW);
        if (bp_ret > 0) {
            printf("failed to insert bp for get_user: %d\n", bp_ret);
        } else {
            printf("Inserted breakpoints for get_user\n");
        }

        bp_ret = kvm_insert_breakpoint(cpu, strnlen_user_addr, 1, GDB_BREAKPOINT_SW);
        if (bp_ret > 0) {
            printf("failed to insert bp for strnlen_user_addr: %d\n", bp_ret);
        } else {
            printf("Inserted breakpoints for strnlen_user_addr\n");
        }

        bp_ret = kvm_insert_breakpoint(cpu, random_bytes_addr, 1, GDB_BREAKPOINT_SW);
        if (bp_ret > 0) {
            printf("failed to insert bp for random_bytes_start_addr: %d\n", bp_ret);
        } else {
            printf("Inserted breakpoints for random_bytes_start_addr\n");
        }

        // if (rr_in_replay()) {
        //     rr_insert_userspace_int(cpu);
        // }
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


__attribute_maybe_unused__ static bool handle_on_bp(CPUState *cpu)
{
    int bp_type;
    target_ulong bp_addr;

    if (!rr_in_record())
        return false;

    if (cpu->singlestep_enabled != 0) {
        if (last_removed_addr == 0) {
            return false;
        }
        
        bp_type = GDB_BREAKPOINT_HW;

        if (rr_is_address_sw(last_removed_addr)) {
            bp_type = GDB_BREAKPOINT_SW;
        }
        if (kvm_insert_breakpoint(cpu, last_removed_addr, 1, bp_type) > 0) {
            printf("failed to insert bp\n");
            abort();
        }
        cpu_single_step(cpu, 0);

        last_removed_addr = 0;

    } else {
        
        bp_type = GDB_BREAKPOINT_HW;

        bp_addr = cpu->kvm_run->debug.arch.pc;

        if (!rr_is_address_interceptible(bp_addr)) {
            return false;
        }

        rr_handle_kernel_entry(cpu, bp_addr);

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

    // rr_insert_breakpoints();

    do {
        if (cpu_can_run(cpu)) {
            r = kvm_cpu_exec(cpu);
            if (r == EXCP_DEBUG) {
                if (!handle_on_bp(cpu)) {
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
