/*
 * Accelerator CPUS Interface
 *
 * Copyright 2020 SUSE LLC
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef KVM_CPUS_H
#define KVM_CPUS_H

#include "sysemu/cpus.h"

int kvm_init_vcpu(CPUState *cpu, Error **errp);
int kvm_cpu_exec(CPUState *cpu);
void kvm_destroy_vcpu(CPUState *cpu);
void kvm_cpu_synchronize_post_reset(CPUState *cpu);
void kvm_cpu_synchronize_post_init(CPUState *cpu);
void kvm_cpu_synchronize_pre_loadvm(CPUState *cpu);

void rr_insert_breakpoints(void);
void rr_remove_breakpoints(void);
void rr_insert_entry_breakpoints(void);

int kvm_start_record(int enable_trace, unsigned long trace_interval);
int kvm_end_record(void);
int kvm_start_replay(void);
int kvm_end_replay(void);
int rr_get_vcpu_events(void);
int rr_get_vcpu_mem_logs(void);
int rr_signal_dma_finish(void);
int kvm_reset_counter(CPUState *cs);
int kvm_reset_interval(CPUState *cs, unsigned long interval);
#endif /* KVM_CPUS_H */
