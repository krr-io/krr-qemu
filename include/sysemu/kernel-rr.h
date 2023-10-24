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


#define SYSCALL 0xffffffff81800000
#define COPY_FROM_ITER 0xffffffff8144af4a
#define COPY_FROM_USER 0xffffffff814528c0
// #define STRNCPY_FROM_USER 0xffffffff81455b00
#define STRNCPY_FROM_USER 0xffffffff814456f0
#define GET_FROM_USER 0xffffffff816c2220
#define STRLEN_USER 0xffffffff814458d2
#define RANDOM_GEN 0xffffffff81533800
#define COPY_PAGE_FROM_ITER_ATOMIC 0xffffffff8144dd68
#define PF_EXEC 0xffffffff81700a20

#define KVM_HC_RR_DATA_IN           13
#define KVM_HC_RR_STRNCPY			14
#define KVM_HC_RR_RANDOM			15
#define KVM_HC_RR_GETUSER			16


// #define SYSCALL 0xffffffff81200000
// #define COPY_FROM_ITER 0xffffffff810afbf1
// #define COPY_FROM_USER 0xffffffff810b4f7d
// #define STRNCPY_FROM_USER 0xffffffff810cbc58
// #define GET_FROM_USER 0xffffffff81118850
// #define STRLEN_USER 0xffffffff810cbe4a
// #define RANDOM_GEN 0xffffffff810e1e25
// #define COPY_PAGE_FROM_ITER_ATOMIC 0xffffffff810b0af1
// #define PF_EXEC 0xffffffff8111e369


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
void rr_do_replay_rand(CPUState *cpu);

uint64_t rr_num_instr_before_next_interrupt(void);
int rr_is_syscall_ready(CPUState *cpu);
void rr_do_replay_io_input(CPUState *cpu, unsigned long *input);
void rr_do_replay_syscall(CPUState *cpu);
void rr_do_replay_exception(CPUState *cpu);
void rr_do_replay_exception_end(CPUState *cpu);
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

typedef struct rr_event_guest_queue_header_t {
    unsigned int current_pos;
    unsigned int total_pos;
    unsigned int header_size;
    unsigned int entry_size;
    unsigned int rr_enabled;
} rr_event_guest_queue_header;

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

void rr_register_ivshmem(RAMBlock *rb);
#endif /* KERNEL_RR_H */
