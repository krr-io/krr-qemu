#ifndef KERNEL_RR_H
#define KERNEL_RR_H
#include <linux/kvm.h>
#include <sys/cdefs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdint.h>

#include "qemu/typedefs.h"

#define RR_DEBUG 1
#define RR_LOG_DEBUG 1
// #include "sysemu/dma.h"

#define RR_GFU_BEGIN 0xffffffff81031720
#define STRNCPY_FROM_USER 0xffffffff8146cf90 // b lib/strncpy_from_user.c:42
#define STRNLEN_USER 0xffffffff8146d120 // info addr strnlen_user
#define RANDOM_GEN 0xffffffff810316b0 // info addr rr_record_random
#define PF_EXEC 0xffffffff8182ed20 // info addr exc_page_fault
#define PF_EXEC_END 0xffffffff8182efc0 // b fault.c:1580 arch/x86/mm/fault.c:1463
#define RR_CFU_BEGIN 0xffffffff81031790
#define RR_RECORD_CFU 0xffffffff81031870 // info addr rr_record_cfu
#define RR_GFU_NOCHECK1 0xffffffff817e8f6e // b arch/x86/lib/getuser.S:127
#define RR_RECORD_GFU 0xffffffff817e8f54 // b getuser.S:103
#define RR_GFU_NOCHECK4 0xffffffff817e8fad // b getuser.S:162
#define RR_GFU_NOCHECK8 0xffffffff817e8fce // b getuser.S:147
#define RR_GFU4 0xffffffff817e8f23 // b getuser.S:88
#define PF_ENTRY 0xffffffff81a00b40 // info addr asm_exc_page_fault
#define RR_PTE_CLEAR 0xffffffff81031b30 // info addr rr_record_pte_clear
#define RR_PTE_READ 0xffffffff81031ba0 // info addr rr_read_pte
#define RR_GFU_CALL_BEGIN 0xffffffff810346b0
#define RR_PTE_READ_ONCE 0xffffffff81031c10

#define RR_IRET 0xffffffff81a00eed // b arch/x86/entry/entry_64.S:702
#define RR_SYSRET 0xffffffff81a00193 // b arch/x86/entry/entry_64.S:226
#define SYSCALL_ENTRY 0xffffffff81a00000 // info addr entry_SYSCALL_64
#define SYSCALL_EXIT 0xffffffff8182f580 // info addr syscall_exit_to_user_mode
#define PF_ASM_EXC 0xffffffff81a00b40 // info addr asm_exc_page_fault
#define INT_ASM_EXC 0xffffffff81a00b00 // info addr asm_exc_int3
#define INT_ASM_DEBUG 0xffffffff81a00b70 // info addr asm_exc_debug

#define IRQ_ENTRY 0xffffffff8182f490 // info addr irqentry_enter
#define IRQ_EXIT 0xffffffff8182f5f0 // info addr irqentry_exit

#define LOCK_RELEASE 0 // info addr rr_record_release
#define RR_RECORD_SYSCALL 0xffffffff8182e5a0 // info addr rr_record_syscall
#define RR_HANDLE_SYSCALL 0xffffffff8128ab80
#define RR_HANDLE_IRQ 0xffffffff81035210
#define RR_RECORD_IRQ 0xffffffff8103523f
#define RR_RECORD_EXCP 0xffffffff810350d1

#define E1000_CLEAN 0xffffffff816056a0
#define E1000_CLEAN_MID 0xffffffff81605a02

#define COSTUMED1 0xffffffff81a00193
#define COSTUMED2 0xffffffff81246eb0
#define COSTUMED3 0xffffffff81246f40


#define KVM_HC_RR_DATA_IN           13
#define KVM_HC_RR_STRNCPY			14
#define KVM_HC_RR_RANDOM			15
#define KVM_HC_RR_GETUSER			16

#define SG_NUM  1024

#define MAX_CPU_NUM 32

#define IO_INST_REP 1
#define IO_INST_REP_OUT 2
#define STO_INST_REP 4
#define INST_REP 8


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
void rr_do_replay_cfu(CPUState *cpu, int post_exception);
void rr_do_replay_rand(CPUState *cpu, int hypercall);
void rr_do_replay_rdseed(unsigned long *val);

uint64_t rr_num_instr_before_next_interrupt(void);
int rr_is_syscall_ready(CPUState *cpu);
void rr_do_replay_io_input(CPUState *cpu, unsigned long *input);
void rr_do_replay_syscall(CPUState *cpu);
void rr_do_replay_exception(CPUState *cpu, int user_mode);
void rr_do_replay_exception_end(CPUState *cpu);
void rr_do_replay_strncpy_from_user(CPUState *cpu, int post_exception);
void rr_post_replay_exception(CPUState *cpu);
void rr_do_replay_rdtsc(CPUState *cpu, unsigned long *tsc);
void rr_do_replay_gfu(CPUState *cpu);
void rr_do_replay_mmio(unsigned long *input);
void rr_do_replay_rdpmc(CPUState *cpu, unsigned long *val);

int rr_get_next_event_type(void);
unsigned long rr_get_next_event_rip(void);
unsigned long rr_one_cpu_rip(void);
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
void handle_rr_checkpoint(CPUState *cpu);

void rr_handle_kernel_entry(CPUState *cpu, unsigned long bp_addr, unsigned long inst_cnt);
void rr_do_replay_strnlen_user(CPUState *cpu);
void rr_do_replay_release(CPUState *cpu);
void rr_do_replay_sync_inst(CPUState *cpu);
void cause_other_cpu_debug(CPUState *cpu);
void sync_syscall_spin_cnt(CPUState *cpu);
void dump_cpus_state(void);
void kvm_prep_buf_event(void);
void try_replay_dma(CPUState *cs, int user_ctx);
int get_lock_owner(void);
int get_cpu_num(void);
int get_record_net(void);
void set_record_net(int val);
unsigned long get_dma_buf_size(void);
void set_trace_mode(int mode);
int get_trace_mode(void);
int addr_in_extra_debug_points(unsigned long addr);
void set_skip_save(int skip);

typedef uint8_t dma_data;

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
    dma_data *buf;
} rr_sg_data;

typedef struct rr_dma_entry_t {
    int len;
    rr_sg_data *sgs[SG_NUM];
    struct rr_dma_entry_t *next;
    int replayed_sgs;
    unsigned long inst_cnt;
    unsigned long rip;
    unsigned long follow_num;
    int cpu_id;
} rr_dma_entry;

typedef struct rr_dma_queue_t {
    rr_dma_entry *front;
    rr_dma_entry *rear;
} rr_dma_queue;


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
unsigned long get_checksum(dma_data *buffer, unsigned long buffersize);
int rr_pop_next_event_type(int event_type);
void inc_replayed_number(void);
int skip_record_dma(void *cb_func);
void register_nvme_cb(void *func);
void set_kernel_only(int konly);
unsigned long get_recorded_num(void);

void rr_register_ivshmem(RAMBlock *rb);
unsigned long rr_get_shm_addr(void);
void rr_ivshmem_set_rr_enabled(int enabled);
int rr_inc_inst(CPUState *cpu, unsigned long next_pc, TranslationBlock *tb);
int replay_cpu_exec_ready(CPUState *cpu);
CPUState* replay_get_running_cpu(void);
void rr_debug(void);
void check_kernel_access(void);
void set_cpu_num(int n);

void dma_enqueue(rr_dma_queue *q, rr_dma_entry *entry);
rr_dma_entry* dma_dequeue(rr_dma_queue* q);
void rr_load_dma_logs(const char *log_file, rr_dma_queue *queue);
void rr_append_network_dma_sg(void *buf, uint64_t len, uint64_t addr);
void rr_end_network_dma_entry(unsigned long inst_cnt, unsigned long rip, int cpu_id);
void rr_save_dma_logs(const char *log_name, rr_dma_entry *entry_head);
void rr_network_dma_post_record(void);
void rr_network_dma_pre_record(void);

void rr_dma_pre_replay(void);
void rr_dma_network_pre_replay(void);
void rr_dma_pre_replay_common(const char *load_file, rr_dma_queue **q);
void init_dma_queue(rr_dma_queue **queue);

rr_dma_entry* rr_fetch_next_network_dme_entry(int cpu_id);

void rr_register_e1000_as(PCIDevice *dev);
void rr_replay_next_network_dma(int cpu_id);
void do_replay_dma_entry(rr_dma_entry *dma_entry, AddressSpace *as);

void append_to_queue(int type, void *opaque);
int get_kernel_only(void);
void set_count_syscall(int val);
void replay_ready(void);
void rr_save_checkpoints(void);
void rr_init_checkpoints(void);
void rr_load_checkpoints(void);
void handle_replay_rr_checkpoint(CPUState *cpu, int is_rep);
int is_valid_op(int op);
void set_should_log(int v);
int is_verify_replay(void);
void rr_do_replay_gfu_begin(CPUState *cpu, int post_exception);
void set_log_bound(unsigned long start, unsigned long end);
void rr_do_replay_pte(CPUState *cpu);
void rr_do_replay_gfu_call_begin(CPUState *cpu);
void add_debug_point(unsigned long addr);
int addr_in_debug_points(unsigned long addr);
void rr_do_remove_breakpoints(CPUState *cpu);
void rr_do_insert_breakpoints(CPUState *cpu);
void rr_do_insert_entry_breakpoints(CPUState *cpu);
void set_checkpoint_interval(int interval);
int get_checkpoint_interval(void);
unsigned long replay_get_inst_cnt(void);
void rr_do_replay_dma(void);
void rr_handle_queue_full(void);
void rr_rotate_shm_queue(void);
int replay_finished(void);
int rr_inject_exception(CPUState *cpu);

#ifdef RR_LOG_DEBUG
#define LOG_MSG(fmt, ...) \
    do { \
        printf(fmt, ##__VA_ARGS__); \
        qemu_log(fmt, ##__VA_ARGS__); \
    } while (0)
#else
#define LOG_MSG(fmt, ...) do {} while (0)
#endif

#endif /* KERNEL_RR_H */
