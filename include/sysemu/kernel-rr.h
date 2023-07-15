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

#define SYSCALL 0xffffffff81200000
#define COPY_FROM_ITER 0xffffffff810afbf1
#define COPY_FROM_USER 0xffffffff810b4f7d
#define STRNCPY_FROM_USER 0xffffffff810cbc58
#define GET_FROM_USER 0xffffffff81118850
#define STRLEN_USER 0xffffffff810cbe4a
#define RANDOM_GEN 0xffffffff810e1e25
#define COPY_PAGE_FROM_ITER_ATOMIC 0xffffffff810b0af1


int rr_in_replay(void);
int rr_in_record(void);
void rr_set_record(int record);
void rr_set_replay(int replay, unsigned long ram_size);
void accel_start_kernel_replay(void);
int replay_should_skip_wait(void);

void rr_replay_interrupt(CPUState *cpu, int *interrupt);
void rr_do_replay_intno(CPUState *cpu, int *intno);
void rr_do_replay_cfu(CPUState *cpu);
void rr_do_replay_rand(CPUState *cpu);

uint64_t rr_num_instr_before_next_interrupt(void);
int rr_is_syscall_ready(CPUState *cpu);
void rr_do_replay_io_input(unsigned long *input);
void rr_do_replay_syscall(CPUState *cpu);
void rr_do_replay_exception(CPUState *cpu);
void rr_do_replay_exception_end(CPUState *cpu);
void rr_do_replay_rdtsc(unsigned long *tsc);

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

typedef struct rr_mem_log_t {
    unsigned long gpa;
    unsigned long rip;
    char md5[34];
    int syscall;
    struct rr_mem_log_t *next;
} rr_mem_log;

typedef struct rr_sg_data_t {
    uint64_t addr;
    uint64_t len;
    uint8_t *buf;
} rr_sg_data;

typedef struct rr_dma_entry_t {
    int len;
    rr_sg_data *sgs[1024];
    struct rr_dma_entry_t *next;
} rr_dma_entry;

rr_mem_log *rr_mem_log_new(void);
void append_mem_log(rr_mem_log *mem_log);
void rr_memlog_post_record(void);
void rr_verify_dirty_mem(void);
void rr_memlog_post_replay(void);

#endif /* KERNEL_RR_H */
