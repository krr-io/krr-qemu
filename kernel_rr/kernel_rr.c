#include "qemu/osdep.h"
#include "qemu-common.h"

#include "cpu.h"

#include "linux-headers/linux/kernel_rr.h"

#include "sysemu/kernel-rr.h"

const char *kernel_rr_log = "kernel_rr.log";

__attribute_maybe_unused__ static int g_rr_in_replay = 0;

unsigned long g_ram_size = 0;

rr_event_log *rr_event_log_head = NULL;
rr_event_log *rr_event_cur = NULL;

static int event_syscall_num = 0;
static int event_exception_num = 0;
static int event_interrupt_num = 0;

static bool log_loaded = false;

uint64_t rr_get_next_event_inst(void)
{
    return rr_event_log_head->inst_cnt;
}

int rr_in_replay(void)
{
    return g_rr_in_replay;
}

void rr_set_replay(int replay, unsigned long ram_size)
{
    g_rr_in_replay = replay;
    g_ram_size = ram_size;
    printf("ram size=%ld\n", ram_size);
    // printf("set kernel replay = %d\n", g_rr_in_replay);
}

void accel_start_kernel_replay(void)
{
    // kvm_start_record();
}

static rr_event_log *rr_event_log_new_from_event(rr_event_log event)
{
    rr_event_log *event_record;

    event_record = rr_event_log_new();

    event_record->type = event.type;
    event_record->inst_cnt = event.inst_cnt;

    switch (event.type)
    {
    case EVENT_TYPE_INTERRUPT:
        memcpy(&event_record->event.interrupt, &event.event.interrupt, sizeof(rr_interrupt));
        // printf("Interrupt: %d\n", event.event.interrupt.lapic.vector);

        printf("Interrupt: %d, inst_cnt: %lu\n", event_record->event.interrupt.lapic.vector, event.inst_cnt);
        event_interrupt_num++;
        break;

    case EVENT_TYPE_EXCEPTION:
        memcpy(&event_record->event.exception, &event.event.exception, sizeof(rr_exception));
        printf("Exception: %d, error code=%d, addr=%lu, inst_cnt: %lu\n",
               event_record->event.exception.exception_index, 
               event_record->event.exception.error_code, event_record->event.exception.cr2,
               event.inst_cnt);
        event_exception_num++;
        break;

    case EVENT_TYPE_SYSCALL:
        memcpy(&event_record->event.syscall, &event.event.syscall, sizeof(rr_syscall));
        event_syscall_num++;
        printf("Syscall: %llu, arg1=%llu, arg2=%llu, inst_cnt: %lu\n",
               event_record->event.syscall.regs.rax,
               event_record->event.syscall.regs.rbx,
               event_record->event.syscall.regs.rcx,
               event.inst_cnt);
        break;

    default:
        break;
    }

    return event_record;
}

void append_event(rr_event_log event)
{
    rr_event_log *event_record = rr_event_log_new_from_event(event);

    if (rr_event_cur == NULL) {
        rr_event_log_head = event_record;
        rr_event_cur = event_record;
    } else {
        rr_event_cur->next = event_record;
        rr_event_cur = rr_event_cur->next;
    }

    rr_event_cur->next = NULL;
}

static void rr_pop_event_head(void) {
    rr_event_log_head = rr_event_log_head->next;
}

rr_event_log *rr_event_log_new(void)
{
    rr_event_log *event = (rr_event_log*)malloc(sizeof(rr_event_log));
    return event;
}

void rr_print_events_stat(void)
{
    printf("interrupt: %d\nsyscall: %d\nexception: %d\n",
           event_interrupt_num, event_syscall_num, event_exception_num);
}

static void persist_bin(rr_event_log *event, FILE *fptr) {
	fwrite(event, sizeof(rr_event_log), 1, fptr);
}

static void rr_save_events(void)
{
    rr_print_events_stat();

	FILE *fptr = fopen(kernel_rr_log, "a");
	rr_event_log *cur= rr_event_log_head;

	while (cur != NULL) {
		persist_bin(cur, fptr);
        cur = cur->next;
	}

	fclose(fptr);
}

static void rr_load_events(void) {
    if (log_loaded) return;

	__attribute_maybe_unused__ FILE *fptr = fopen(kernel_rr_log, "r");

    rr_event_log loaded_node;

	while(fread(&loaded_node, sizeof(rr_event_log), 1, fptr)) {
		append_event(loaded_node);
	}
	
    rr_print_events_stat();
    log_loaded = true;
}

static void rr_clear_redundant_events(CPUState *cpu)
{
    while (rr_event_log_head != NULL && 
           rr_event_log_head->inst_cnt >= cpu->rr_guest_instr_count) {
        rr_event_log_head = rr_event_log_head->next;
    }
}

void rr_post_record(void)
{
    rr_save_events();
}

void rr_pre_replay(void)
{
    rr_load_events();
}

void rr_replay_interrupt(CPUState *cpu, int *interrupt)
{
    if (rr_event_log_head == NULL) {
        *interrupt = -1;
        return;
    }

    if (rr_event_log_head->type == EVENT_TYPE_INTERRUPT) {

        if (rr_event_log_head->inst_cnt == cpu->rr_guest_instr_count) {
            *interrupt = CPU_INTERRUPT_HARD;
            printf("replay int request\n");
        }
        return;
    }

    *interrupt = -1;
    return;
}

void rr_do_replay_intno(CPUState *cpu, int *intno)
{
    if (rr_event_log_head == NULL) {
        printf("No events anymore\n");
        abort();
    }

    if (rr_event_log_head->type == EVENT_TYPE_INTERRUPT) {
        *intno = rr_event_log_head->event.interrupt.lapic.vector;
        rr_pop_event_head();
        rr_clear_redundant_events(cpu);

        printf("replayed %d\n", *intno);
        return;
    }
}

uint64_t rr_num_instr_before_next_interrupt(void)
{
    if (rr_event_log_head == NULL) rr_load_events();

    return rr_event_log_head->inst_cnt;
}
