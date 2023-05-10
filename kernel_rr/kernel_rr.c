#include "qemu/osdep.h"
#include "qemu-common.h"
#include "exec/log.h"

#include "cpu.h"

#include "linux-headers/linux/kernel_rr.h"

#include "sysemu/kernel-rr.h"

#include "exec/cpu-common.h"

const char *kernel_rr_log = "kernel_rr.log";

__attribute_maybe_unused__ static int g_rr_in_replay = 0;
__attribute_maybe_unused__ static int g_rr_in_record = 0;

unsigned long g_ram_size = 0;

rr_event_log *rr_event_log_head = NULL;
rr_event_log *rr_event_cur = NULL;

static int event_syscall_num = 0;
static int event_exception_num = 0;
static int event_interrupt_num = 0;
static int event_io_input_num = 0;
static int event_cfu_num = 0;

static int started_replay = 0;
static int initialized_replay = 0;

static int replayed_interrupt_num = 0;

static int replayed_event_num = 0;

static bool log_loaded = false;

static void rr_pop_event_head(void);

uint64_t rr_get_next_event_inst(void)
{
    return rr_event_log_head->inst_cnt;
}

int rr_get_next_event_type(void)
{
    return rr_event_log_head->type;
}

int rr_in_record(void)
{
    return g_rr_in_record;
}

int rr_in_replay(void)
{
    // return false;
    return g_rr_in_replay;
}

void rr_set_record(int record)
{
    g_rr_in_record = 1;
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

void rr_do_replay_cfu(CPUState *cpu)
{
    if (rr_event_log_head->type != EVENT_TYPE_CFU) {
        printf("Expected log copy from user, but got %d\n", rr_event_log_head->type);
        abort();
    }

    printf("Replaying CFU\n");
    int ret = cpu_memory_rw_debug(cpu, rr_event_log_head->event.cfu.src_addr,
                rr_event_log_head->event.cfu.data, rr_event_log_head->event.cfu.len, true);
    
    if (ret < 0) {
        printf("Failed to write to address %lx: %d\n", rr_event_log_head->event.cfu.src_addr, ret);
    }

    rr_pop_event_head();

    return;
}

static rr_event_log *rr_event_log_new_from_event(rr_event_log event)
{
    rr_event_log *event_record;

    event_record = rr_event_log_new();

    event_record->type = event.type;
    event_record->inst_cnt = event.inst_cnt;
    event_record->rip = event.rip;

    int event_num = event_syscall_num + event_exception_num + event_interrupt_num + event_io_input_num + 1;

    switch (event.type)
    {
    case EVENT_TYPE_INTERRUPT:
        memcpy(&event_record->event.interrupt, &event.event.interrupt, sizeof(rr_interrupt));

        qemu_log("Interrupt: %d, inst_cnt: %lu, rip=%lx, number=%d\n",
                 event_record->event.interrupt.lapic.vector,
                 event.inst_cnt, event_record->rip, event_num);
        event_interrupt_num++;
        break;

    case EVENT_TYPE_EXCEPTION:
        memcpy(&event_record->event.exception, &event.event.exception, sizeof(rr_exception));

        qemu_log("PF exception: %d, inst_cnt: %lu, number=%d\n",
               event_record->event.exception.exception_index, event.inst_cnt, event_num);
        event_exception_num++;
        break;

    case EVENT_TYPE_SYSCALL:
        memcpy(&event_record->event.syscall, &event.event.syscall, sizeof(rr_syscall));
        qemu_log("Syscall: %llu, inst_cnt: %lu, number=%d\n",
                 event_record->event.syscall.regs.rax, event.inst_cnt, event_num);
        event_syscall_num++;
        break;

     case EVENT_TYPE_IO_IN:
        memcpy(&event_record->event.io_input, &event.event.io_input, sizeof(rr_io_input));
        qemu_log("IO Input: %lx, rip=%lx, number=%d\n",
                 event_record->event.io_input.value, event_record->rip, event_num);
        event_io_input_num++;
        break;
    case EVENT_TYPE_CFU:
        memcpy(&event_record->event.cfu, &event.event.cfu, sizeof(rr_cfu));
        qemu_log("CFU: %lx, rip=%lx, number=%d\n",
                 event_record->event.cfu.src_addr, event_record->rip, event_num);
        event_cfu_num++;
        break;
    default:
        break;
    }

    return event_record;
}

int rr_is_syscall_ready(CPUState *cpu)
{
    if (rr_event_log_head == NULL) {
        printf("Replay is over");
        exit(0);
    }

    if (rr_event_log_head->type == EVENT_TYPE_SYSCALL && cpu->rr_guest_instr_count == rr_event_log_head->inst_cnt) {
        return 1;
    }

    return 0;
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

    // rr_pop_event_head();
    // rr_pop_event_head();
}

__attribute_maybe_unused__ static void rr_clear_redundant_events(CPUState *cpu)
{
    while (rr_event_log_head != NULL && 
           rr_event_log_head->inst_cnt <= cpu->rr_executed_inst) {
        rr_event_log_head = rr_event_log_head->next;
    }
}

void rr_post_record(void)
{
    rr_save_events();
}

// void rr_pre_replay(void)
// {
//     rr_load_events();
// }

void rr_replay_interrupt(CPUState *cpu, int *interrupt)
{    
    X86CPU *x86_cpu;
    CPUArchState *env;

    if (rr_event_log_head == NULL) {
        if (started_replay) {
            printf("Replay finished\n");
            exit(0);
        }

        *interrupt = -1;
        return;
    }

    if (rr_event_log_head->type == EVENT_TYPE_INTERRUPT) {
        if (rr_event_log_head->inst_cnt == cpu->rr_executed_inst) {

            x86_cpu = X86_CPU(cpu);
            env = &x86_cpu->env;
        
            if (env->eip == rr_event_log_head->rip) {
                *interrupt = CPU_INTERRUPT_HARD;
                qemu_log("Ready to replay int request\n");
                cpu->rr_executed_inst++;
            } else {
                printf("Mismatched, interrupt=%d inst number=%lu and rip=0x%lx\n", 
                       rr_event_log_head->event.interrupt.lapic.vector, rr_event_log_head->inst_cnt,
                       rr_event_log_head->rip);
                abort();
            }
            return;
        }
    }

    *interrupt = -1;
    return;
}

void rr_do_replay_syscall(CPUState *cpu)
{
    X86CPU *x86_cpu;
    CPUArchState *env;

    assert(rr_event_log_head->type == EVENT_TYPE_SYSCALL);

    cpu->rr_executed_inst = rr_event_log_head->inst_cnt;

    x86_cpu = X86_CPU(cpu);
    env = &x86_cpu->env;

    env->regs[R_EAX] = rr_event_log_head->event.syscall.regs.rax;
    env->regs[R_EBX] = rr_event_log_head->event.syscall.regs.rbx;
    env->regs[R_ECX] = rr_event_log_head->event.syscall.regs.rcx;
    env->regs[R_EDX] = rr_event_log_head->event.syscall.regs.rdx;
    env->regs[R_EBP] = rr_event_log_head->event.syscall.regs.rbp;
    env->regs[R_ESP] = rr_event_log_head->event.syscall.regs.rsp;
    env->regs[R_EDI] = rr_event_log_head->event.syscall.regs.rdi;
    env->regs[R_ESI] = rr_event_log_head->event.syscall.regs.rsi;
    env->regs[R_R8] = rr_event_log_head->event.syscall.regs.r8;
    env->regs[R_R9] = rr_event_log_head->event.syscall.regs.r9;
    env->regs[R_R10] = rr_event_log_head->event.syscall.regs.r10;
    env->regs[R_R11] = rr_event_log_head->event.syscall.regs.r11;
    env->regs[R_R12] = rr_event_log_head->event.syscall.regs.r12;
    env->regs[R_R13] = rr_event_log_head->event.syscall.regs.r13;
    env->regs[R_R14] = rr_event_log_head->event.syscall.regs.r14;
    env->regs[R_R15] = rr_event_log_head->event.syscall.regs.r15;

    replayed_event_num++;
    rr_pop_event_head();

    qemu_log("Replayed syscall=%lu, replayed event number=%d\n", env->regs[R_EAX], replayed_event_num);
    printf("Replayed syscall=%lu, replayed event number=%d\n", env->regs[R_EAX], replayed_event_num);
}

void rr_do_replay_io_input(unsigned long *input)
{
    if (rr_event_log_head->type != EVENT_TYPE_IO_IN) {
        printf("Expected %d event, found %d", EVENT_TYPE_IO_IN, rr_event_log_head->type);
        abort();
    }

    replayed_event_num++;

    *input = rr_event_log_head->event.io_input.value;
    rr_pop_event_head();

    qemu_log("Replayed io input=%lx, replayed event number=%d\n", *input, replayed_event_num);
    printf("Replayed io input=%lx, replayed event number=%d\n", *input, replayed_event_num);
}

void rr_do_replay_intno(CPUState *cpu, int *intno)
{
    X86CPU *x86_cpu;
    CPUArchState *env;

    if (rr_event_log_head == NULL) {
        qemu_log("No events anymore\n");
        abort();
    }

    if (rr_event_log_head->type == EVENT_TYPE_INTERRUPT) {
        x86_cpu = X86_CPU(cpu);
        env = &x86_cpu->env;
    
        *intno = rr_event_log_head->event.interrupt.lapic.vector;
        rr_pop_event_head();

        if (!started_replay) {
            started_replay = 1;
        }

        replayed_interrupt_num++;
        replayed_event_num++;

        qemu_log("Replayed interrupt vector=%d, RIP on replay=0x%lx, replayed event number=%d\n",
                 *intno, env->eip, replayed_event_num);
        printf("Replayed interrupt vecotr=%d, RIP on replay=0x%lx, replayed event number=%d\n",
               *intno, env->eip, replayed_event_num);
        return;
    }
}

uint64_t rr_num_instr_before_next_interrupt(void)
{
    if (rr_event_log_head == NULL) {
        if (!initialized_replay) {
            rr_load_events();
            initialized_replay = 1;
        } else {
            printf("Replay finished\n");
            exit(0);
        }
    }

    return rr_event_log_head->inst_cnt;
}

int replay_should_skip_wait(void)
{
    return started_replay;
}

void rr_trap(void) {
    return;
}
