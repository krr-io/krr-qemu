#ifndef __KERNEL_RR_H__
#define __KERNEL_RR_H__
#include <stdint.h>
#include <linux/kvm.h>

#define EVENT_TYPE_INTERRUPT 0
#define EVENT_TYPE_EXCEPTION 1
#define EVENT_TYPE_SYSCALL   2
#define EVENT_TYPE_IO_IN     3
#define EVENT_TYPE_CFU       4

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
    unsigned long value;
} rr_io_input;

typedef struct {
    unsigned long src_addr;
    unsigned long dest_addr;
    unsigned long len;
    unsigned long rdx;
    uint8_t data[1024];
} rr_cfu;

typedef struct {
    lapic_log lapic;
} rr_interrupt;

typedef struct {
    int exception_index;
    int error_code;
    unsigned long cr2;
    struct kvm_regs regs;
} rr_exception;

typedef struct {
    struct kvm_regs regs;
} rr_syscall;

typedef struct rr_event_log_t{
    int type;
    union {
        rr_interrupt interrupt;
        rr_exception exception;
        rr_syscall  syscall;
        rr_io_input io_input;
        rr_cfu cfu;
    } event;
    struct rr_event_log_t *next;
    uint64_t inst_cnt;
    unsigned long rip;
} rr_event_log;

typedef struct rr_event_list_t {
    rr_event_log *item;
    int length;
} rr_event_list;

struct rr_event_info {
    int event_number;
};


// RR functions

void append_event(rr_event_log event);
rr_event_log *rr_event_log_new(void);
void rr_print_events_stat(void);

void rr_post_record(void);
void rr_pre_replay(void);

uint64_t rr_get_next_event_inst(void);

#endif
