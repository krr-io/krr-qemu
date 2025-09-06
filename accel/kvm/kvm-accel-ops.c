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
#include "migration/snapshot.h"

// checkpoint mutex
static QemuMutex cp_mutex;
static QemuCond cp_cond;

static int in_single_step = -1;
static bool started_bp_handle = false;


static void cp_mutex_lock_init(void)
{
    qemu_mutex_init(&cp_mutex);
    qemu_cond_init(&cp_cond);
}

__attribute_maybe_unused__ static void cp_mutex_lock(void)
{
    qemu_mutex_lock(&cp_mutex);
}

__attribute_maybe_unused__ static void cp_mutex_unlock(void)
{
    qemu_mutex_unlock(&cp_mutex);
}


static bool rr_is_address_interceptible(target_ulong bp_addr)
{
    if (addr_in_debug_points(bp_addr))
        return true;

    return false;
}

static bool rr_is_address_sw(target_ulong bp_addr)
{
    if (addr_in_debug_points(bp_addr))
        return true;

    return false;
}


void rr_insert_entry_breakpoints(void)
{
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        rr_do_insert_entry_breakpoints(cpu);
        return;
    }
}


void rr_insert_breakpoints(void)
{
    __attribute_maybe_unused__ int bp_ret ;
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        rr_do_insert_breakpoints(cpu);
        return;
    }
}

void rr_remove_breakpoints(void)
{
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        rr_do_remove_breakpoints(cpu);
        return;
    }
}


__attribute_maybe_unused__ static void
handle_bp_points(CPUState *cpu, target_ulong bp_addr)
{
    if (addr_in_extra_debug_points(bp_addr) && !cpu->singlestep_enabled)
        rr_handle_kernel_entry(cpu, bp_addr, rr_get_inst_cnt(cpu));
}


unsigned long last_lock_start = 0;

__attribute_maybe_unused__ static bool
handle_on_bp(CPUState *cpu)
{
    int bp_type;
    target_ulong bp_addr;
    int ret;
    bool handled = false;

    bp_addr = cpu->kvm_run->debug.arch.pc;

    if (!rr_in_record())
        return false;

    cp_mutex_lock();
    if (started_bp_handle) {
        handled = true;
        goto end;
    }

    if (in_single_step >= 0 && in_single_step != cpu->cpu_index) {
        handled = true;
        goto end;
    }

    started_bp_handle = true;

    cp_mutex_unlock();
    pause_all_vcpus_no_clock();
    cp_mutex_lock();

    if (cpu->singlestep_enabled && cpu->force_singlestep) {
        handled = true;
        goto finish;
    }

    handle_rr_checkpoint(cpu);

    if (cpu->singlestep_enabled != 0) {
        if (cpu->last_removed_addr == 0) {
            goto finish;
        }

        bp_type = GDB_BREAKPOINT_HW;

        if (rr_is_address_sw(cpu->last_removed_addr)) {
            bp_type = GDB_BREAKPOINT_SW;
        }

        cp_mutex_unlock();

        if (cpu->last_removed_addr > 0) {
            ret = kvm_insert_breakpoint(cpu, cpu->last_removed_addr, 1, bp_type);
            if (ret != 0) {
                printf("failed to insert bp %d\n", ret);
                abort();
            }
            cpu_single_step(cpu, 0);
            cpu->last_removed_addr = 0;
        }

        cp_mutex_lock();
        in_single_step = -1;
    } else {
        
        bp_type = GDB_BREAKPOINT_HW;

        if (!rr_is_address_interceptible(bp_addr)) {
            goto finish;
        }

        // handle_bp_points(cpu, bp_addr);

        if (rr_is_address_sw(bp_addr)) {
            bp_type = GDB_BREAKPOINT_SW;
        }

        in_single_step = cpu->cpu_index;
        cp_mutex_unlock();
        ret = kvm_remove_breakpoint(cpu, bp_addr, 1, bp_type);
        if (ret != 0) {
            printf("failed to remove bp 0x%lx: %d\n", bp_addr, ret);
            abort();
        }
        cpu_single_step(cpu, SSTEP_ENABLE | SSTEP_NOIRQ);
        cpu->last_removed_addr = bp_addr;
        cp_mutex_lock();
        
    }

    handled = true;

finish:
    resume_all_vcpus();
    started_bp_handle = false;

end:
    cp_mutex_unlock();
    return handled;
}


static int start_record(void)
{
    Error *err = NULL;
    int interval;
    int trace_mode;
    int r;

    if (rr_get_ignore_record()) {
        FILE* file = fopen("/dev/shm/record", "w");
        fclose(file);
        return 0;
    }

    printf("start record\n");
    // vm_stop(RUN_STATE_PAUSED);
    pause_all_vcpus();
    rr_ivshmem_set_rr_enabled(1);

    printf("Paused VM, start taking snapshot\n");
    rr_save_snapshot("test1", &err);

    interval = get_checkpoint_interval();

    trace_mode = get_trace_mode();

    if (interval == 0) {
        if (trace_mode == 2) {
            printf("Breakpoint trace is enabled\n");
            rr_insert_breakpoints();
        }
        r = kvm_start_record(0, 0);
    } else {
        rr_insert_entry_breakpoints();
        r = kvm_start_record(1, interval);
    }

    resume_all_vcpus();
    // vm_start();

    return r;
}

static void end_record(void)
{
    if (rr_in_record()) {
        pause_all_vcpus();
        kvm_end_record();
    } else
        rr_get_result();
}

static void *kvm_vcpu_thread_fn(void *arg)
{
    CPUState *cpu = arg;
    int r;

    cp_mutex_lock_init();

    // __attribute_maybe_unused__ unsigned long inst_cnt;

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

            if (r == EXCP_START_RECORD) {
                if (start_record() != 0) {
                    printf("Failed to start record, exiting\n");
                    exit(1);
                }
                continue;
            }

            if (r == EXCP_END_RECORD) {
                end_record();
                continue;
            }

            if (r == EXCP_KRR_ERR) {
                if (krr_get_config().gdb_trap_error) {
                    cpu_handle_guest_debug(cpu);
                }
                continue;
            }

            if (r == EXCP_DEBUG) {
                if (!handle_on_bp(cpu)) {
                    // handle_bp_points(cpu, cpu->kvm_run->debug.arch.pc);
                    // handle_rr_checkpoint(cpu);
                    cpu_handle_guest_debug(cpu);
                }
            }

            if (r == EXCP_RR_CP) {
                handle_rr_checkpoint(cpu);
            }

            if (r == EXCP_QUEUE_FULL) {
                rr_handle_queue_full();
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
