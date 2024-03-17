#ifndef __KERNEL_RR_H__
#define __KERNEL_RR_H__
#include <stdint.h>
#include <linux/kvm.h>

#define EVENT_TYPE_INTERRUPT 0
#define EVENT_TYPE_EXCEPTION 1
#define EVENT_TYPE_SYSCALL   2
#define EVENT_TYPE_IO_IN     3
#define EVENT_TYPE_CFU       4
#define EVENT_TYPE_RANDOM    5
#define EVENT_TYPE_RDTSC     6
#define EVENT_TYPE_DMA_DONE  7
#define EVENT_TYPE_GFU       8
#define EVENT_TYPE_STRNLEN   9
#define EVENT_TYPE_RDSEED    10
#define EVENT_TYPE_RELEASE   11
#define EVENT_TYPE_INST_SYNC 12

enum REGS {
    ZERO,
    RR_RAX,
    RR_RCX,
	RR_RDX,
	RR_RBX,
	RR_RSP,
	RR_RBP,
	RR_RSI,
	RR_RDI,
	RR_R8,
	RR_R9,
	RR_R10,
	RR_R11,
	RR_R12,
	RR_R13,
	RR_R14,
	RR_R15,
	RR_RIP,
	RR_NR_VCPU_REGS,
};

typedef struct {
    int delivery_mode;
	int vector;
    int trig_mode;
} lapic_log;

typedef struct {
    unsigned long src_addr;
    unsigned long dest_addr;
    unsigned long len;
    unsigned long rdx;
    uint8_t data[4096];
} rr_cfu;

typedef struct {
    unsigned long value;
} rr_io_input;

typedef struct {
    unsigned int vector;
    unsigned long ecx;
    int from;
    unsigned long spin_count;
} rr_interrupt;


typedef struct {
    unsigned long val;
} rr_gfu;


typedef struct {
    int exception_index;
    int error_code;
    unsigned long cr2;
    struct kvm_regs regs;
    unsigned long spin_count;
} rr_exception;

typedef struct {
    struct kvm_regs regs;
    unsigned long kernel_gsbase, msr_gsbase, cr3;
    unsigned long spin_count;
} rr_syscall;

typedef struct {
    unsigned long buf;
    unsigned long len;
    uint8_t data[1024];
} rr_random;

typedef struct rr_event_log_t{
    int type;
    int id;
    union {
        rr_interrupt interrupt;
        rr_exception exception;
        rr_syscall  syscall;
        rr_io_input io_input;
        rr_cfu cfu;
        rr_random rand;
        rr_gfu gfu;
    } event;
    struct rr_event_log_t *next;
    uint64_t inst_cnt;
    unsigned long rip;
} rr_event_log;

typedef struct rr_mem_access_log_t {
    unsigned long gpa;
    unsigned long rip;
    unsigned long inst_cnt;
    struct rr_mem_access_log_t *next;
} rr_mem_access_log;

typedef struct rr_event_list_t {
    rr_event_log *item;
    int length;
} rr_event_list;

struct rr_event_info {
    int event_number;
};


// RR functions

void append_event(rr_event_log event, int is_record);
rr_event_log *rr_event_log_new(void);
void rr_print_events_stat(void);

void rr_post_record(void);
void rr_pre_replay(void);

uint64_t rr_get_next_event_inst(void);
// void rr_init_dirty_bitmaps(void);
void rr_create_mem_log(int syscall, unsigned long gpa, unsigned long rip, unsigned long inst_cnt);
void rr_finish_mem_log(void);
void rr_load_mem_logs(void);
int rr_mem_logs_enabled(void);
void rr_enable_mem_logs(void);

struct rr_record_data {
    unsigned long shm_base_addr;
};

typedef struct rr_event_guest_queue_header_t {
    unsigned int current_pos;
    unsigned int total_pos;
    unsigned int header_size;
    unsigned int entry_size;
    unsigned int rr_enabled;
} rr_event_guest_queue_header;


typedef struct rr_event_log_guest_t {
    int type;
    int id;
    union {
        rr_interrupt interrupt;
        rr_exception exception;
        rr_syscall  syscall;
        rr_io_input io_input;
        rr_cfu cfu;
        rr_random rand;
        rr_gfu gfu;
    } event;
    unsigned long inst_cnt;
    unsigned long rip;
} rr_event_log_guest;

#endif
