#ifndef KERNEL_RR_H
#define KERNEL_RR_H
#include <linux/kvm.h>
#include <sys/cdefs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdint.h>

#include "qemu/typedefs.h"
// #include "sysemu/dma.h"


#define STRNCPY_FROM_USER 0xffffffff814b9d10 // info addr strncpy_from_user
#define STRNLEN_USER 0xffffffff814b9f14 // b lib/strnlen_user.c:116
#define RANDOM_GEN 0xffffffff810352d0 // info addr rr_record_random
#define PF_EXEC 0xffffffff81887bf0 // info addr exc_page_fault
#define PF_EXEC_END 0xffffffff81887e90 // b fault.c:1580
#define RR_RECORD_CFU 0xffffffff81035340 // info addr rr_record_cfu
#define RR_RECORD_GFU 0xffffffff81848a24 // b getuser.S:103
#define RR_GFU_NOCHECK4 0xffffffff81848a7d // b getuser.S:147
#define RR_GFU_NOCHECK8 0xffffffff81848a9e // b getuser.S:162
#define RR_GFU4 0xffffffff818489f3 // b getuser.S:88

#define SYSCALL_ENTRY 0xffffffff81a00000 // info addr entry_SYSCALL_64
#define SYSCALL_EXIT 0xffffffff81888560 // info addr syscall_exit_to_user_mode
#define PF_ASM_EXC 0xffffffff81a00b40 // info addr asm_exc_page_fault

#define IRQ_ENTRY 0xffffffff81888600 // info addr irqentry_enter
#define IRQ_EXIT 0xffffffff81888690 // info addr irqentry_exit

#define LOCK_RELEASE 0xffffffff81034f4a // info addr rr_record_release
#define RR_RECORD_SYSCALL 0xffffffff81034fb1 // info addr rr_record_syscall
#define RR_HANDLE_SYSCALL 0xffffffff81034f80
#define RR_HANDLE_IRQ 0xffffffff81035210
#define RR_RECORD_IRQ 0xffffffff8103523f
#define RR_RECORD_EXCP 0xffffffff810350d1


#define KVM_HC_RR_DATA_IN           13
#define KVM_HC_RR_STRNCPY			14
#define KVM_HC_RR_RANDOM			15
#define KVM_HC_RR_GETUSER			16


int rr_in_replay(void);
int rr_in_record(void);
void rr_set_record(int record);
void rr_set_replay(int replay, unsigned long ram_size);
void accel_start_kernel_replay(void);
int replay_should_skip_wait(void);
void rr_pop_event_head(void);
int get_replayed_event_num(void);

void rr_replay_interrupt(CPUState *cpu, int *interrupt);
void rr_do_replay_intno(CPUState *cpu, int *intno);
void rr_do_replay_cfu(CPUState *cpu);
void rr_do_replay_rand(CPUState *cpu, int hypercall);
void rr_do_replay_rdseed(unsigned long *val);

uint64_t rr_num_instr_before_next_interrupt(void);
int rr_is_syscall_ready(CPUState *cpu);
void rr_do_replay_io_input(CPUState *cpu, unsigned long *input);
void rr_do_replay_syscall(CPUState *cpu);
void rr_do_replay_exception(CPUState *cpu);
void rr_do_replay_exception_end(CPUState *cpu);
void rr_do_replay_strncpy_from_user(CPUState *cpu);
void rr_post_replay_exception(CPUState *cpu);
void rr_do_replay_rdtsc(CPUState *cpu, unsigned long *tsc);
void rr_do_replay_gfu(CPUState *cpu);

int rr_get_next_event_type(void);
unsigned long rr_get_next_event_rip(void);
rr_event_log* rr_get_next_event(void);

void rr_take_snapshot(char *ss_name);

void rr_fake_call(void);

void rr_trap(void);
void rr_check_for_breakpoint(unsigned long addr, CPUState *cpu);
void rr_check_breakpoint_start(void);

void rr_gdb_set_stopped(int stopped);
int rr_is_gdb_stopped(void);

void sync_dirty_pages(CPUState *cpu);
void rr_init_dirty_bitmaps(void);
void rr_store_op(CPUArchState *env, unsigned long addr);
unsigned long rr_get_inst_cnt(CPUState *cpu);
unsigned long rr_get_result_buffer(void);
void rr_get_result(void);
void rr_enable_exit_record(void);
void rr_enable_ignore_record(void);
int rr_get_ignore_record(void);

void rr_handle_kernel_entry(CPUState *cpu, unsigned long bp_addr, unsigned long inst_cnt);
void rr_do_replay_strnlen_user(CPUState *cpu);
void rr_do_replay_release(CPUState *cpu);
void rr_do_replay_sync_inst(CPUState *cpu);
void cause_other_cpu_debug(CPUState *cpu);
void sync_syscall_spin_cnt(CPUState *cpu);
void dump_cpus_state(void);

typedef uint64_t sg_addr;

typedef struct rr_mem_log_t {
    unsigned long gpa;
    unsigned long rip;
    unsigned long inst_cnt;
    char md5[34];
    int syscall;
    struct rr_mem_log_t *next;
} rr_mem_log;

typedef struct rr_sg_data_t {
    uint64_t addr;
    uint64_t len;
    unsigned long checksum;
    sg_addr *buf;
} rr_sg_data;

typedef struct rr_dma_entry_t {
    int len;
    rr_sg_data *sgs[1024];
    struct rr_dma_entry_t *next;
    int replayed_sgs;
} rr_dma_entry;

rr_mem_log *rr_mem_log_new(void);
void append_mem_log(rr_mem_log *mem_log);
void rr_memlog_post_record(void);
void rr_verify_dirty_mem(CPUState *cpu);
void rr_memlog_post_replay(void);
void rr_pre_mem_record(void);
void rr_replay_dma_entry(void);
int get_md5sum(void* buffer,
               unsigned long buffersize,
               char* checksum);
unsigned long get_checksum(sg_addr *buffer, unsigned long buffersize);
int rr_pop_next_event_type(int event_type);
void inc_replayed_number(void);
int skip_record_dma(void *cb_func);
void register_nvme_cb(void *func);
void set_kernel_only(int konly);

void rr_register_ivshmem(RAMBlock *rb);
unsigned long rr_get_shm_addr(void);
void rr_ivshmem_set_rr_enabled(int enabled);
int rr_inc_inst(CPUState *cpu, unsigned long next_pc);
int replay_cpu_exec_ready(CPUState *cpu);
CPUState* replay_get_running_cpu(void);
void rr_debug(void);

#endif /* KERNEL_RR_H */
