#define OPENSSL_API_COMPAT 0x10100000L

#include<openssl/md5.h>

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "exec/log.h"
#include "migration/snapshot.h"

#include "cpu.h"

#include "linux-headers/linux/kernel_rr.h"

#include "exec/memory.h"
#include "exec/address-spaces.h"

#include "sysemu/kernel-rr.h"
#include "sysemu/dma.h"
#include "accel/kvm/kvm-cpus.h"

#include "sysemu/kvm.h"
#include "exec/cpu-common.h"
#include "migration/ram.h"
#include "exec/ram_addr.h"
#include "migration/migration.h"
#include "qemu/main-loop.h"
#include "memory.h"

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
static int event_random_num = 0;
static int event_dma_done = 0;

static int started_replay = 0;
static int initialized_replay = 0;

static int replayed_interrupt_num = 0;

static int replayed_event_num = 0;
static int total_event_number = 0;

static bool log_loaded = false;

static int bt_started = 0;
static unsigned long bp = 0xffffffff8108358f;

static int gdb_stopped = 1;

// int64_t replay_start_time = 0;
static unsigned long dirty_page_num = 0;

void rr_fake_call(void){return;}


static void rr_init_ram_bitmaps(void) {
    RAMBlock *block;
    unsigned long pages;
    uint8_t shift = 18;

    /* Skip setting bitmap if there is no RAM */
    if (ram_bytes_total()) {
        if (shift > CLEAR_BITMAP_SHIFT_MAX) {
            error_report("clear_bitmap_shift (%u) too big, using "
                         "max value (%u)", shift, CLEAR_BITMAP_SHIFT_MAX);
            shift = CLEAR_BITMAP_SHIFT_MAX;
        } else if (shift < CLEAR_BITMAP_SHIFT_MIN) {
            error_report("clear_bitmap_shift (%u) too small, using "
                         "min value (%u)", shift, CLEAR_BITMAP_SHIFT_MIN);
            shift = CLEAR_BITMAP_SHIFT_MIN;
        }

        RAMBLOCK_FOREACH_NOT_IGNORED(block) {
            pages = block->max_length >> TARGET_PAGE_BITS;
            /*
             * The initial dirty bitmap for migration must be set with all
             * ones to make sure we'll migrate every guest RAM page to
             * destination.
             * Here we set RAMBlock.bmap all to 1 because when rebegin a
             * new migration after a failed migration, ram_list.
             * dirty_memory[DIRTY_MEMORY_MIGRATION] don't include the whole
             * guest memory.
             */
            block->bmap = bitmap_new(pages);
            bitmap_set(block->bmap, 0, pages);
            block->clear_bmap_shift = shift;
            block->clear_bmap = bitmap_new(clear_bmap_size(pages, shift));
        }
    }
}

static void finish_replay(void)
{
    printf("Replay finished\n");
    rr_print_events_stat();

    rr_memlog_post_replay();
    exit(0);
}

static void pre_record(void) {
    printf("Removing existing log files\n");
    remove(kernel_rr_log);

    rr_pre_mem_record();
    rr_dma_pre_record();
}

void rr_init_dirty_bitmaps(void) {

    if (rr_ram_save_setup(get_ram_state()) != 0) {
        printf("Failed to init ram state\n");
        abort();
    }

    /* For memory_global_dirty_log_start below.  */
    // qemu_mutex_lock_iothread();
    qemu_mutex_lock_ramlist();

    WITH_RCU_READ_LOCK_GUARD() {
        rr_init_ram_bitmaps();
        memory_global_dirty_log_start(GLOBAL_DIRTY_MIGRATION);
    }
    qemu_mutex_unlock_ramlist();
    // qemu_mutex_unlock_iothread();

    /*
     * After an eventual first bitmap sync, fixup the initial bitmap
     * containing all 1s to exclude any discarded pages from migration.
     */
    // migration_bitmap_clear_discarded_pages(rs);
}


__attribute_maybe_unused__ static void track_dirty_pages(RAMBlock *rb)
{
    uint64_t new_dirty_pages =
        cpu_physical_memory_sync_dirty_bitmap(rb, 0, rb->used_length);

    if (new_dirty_pages > 0) {
        printf("new_dirty_pages: %lu\n", new_dirty_pages);
    }

    dirty_page_num += new_dirty_pages;
}

static unsigned long rr_get_syscall_num(CPUState *cpu)
{
    X86CPU *x86_cpu;
    CPUArchState *env;

    x86_cpu = X86_CPU(cpu);
    env = &x86_cpu->env;

    return env->regs[R_EAX];
}


void sync_dirty_pages(CPUState *cpu) {
    unsigned long syscall;

    kvm_cpu_synchronize_state(cpu);

    kernel_rr_sync_dirty_memory();

    syscall = rr_get_syscall_num(cpu);

    rr_create_mem_log(syscall, 0, 0, 0);
    rr_get_vcpu_mem_logs();

    qemu_log("[mem_trace] Syscall: %lu\n", syscall);
}


// static int entered_exception = 0;


void rr_take_snapshot(char *ss_name)
{
    Error *err = NULL;
    // char path[20];

    // if (rr_in_record()) {
    //     strcat(path, "record/");
    // } else {
    //     strcat(path, "replay/");
    // }

    // strcat(path, ss_name);

    rr_save_snapshot(ss_name, &err);
    // save_snapshot(ss_name, true, NULL, false, NULL, &err);

    if (err != NULL) {
        printf("Failed to tabke snapshot");
        abort();
    }

    return;
}

rr_event_log* rr_get_next_event(void)
{
    if (rr_event_log_head == NULL) {
        finish_replay();
    }

    return rr_event_log_head;
}

unsigned long rr_get_next_event_rip(void)
{
    return rr_event_log_head->rip;
}

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
    if (record) {
        pre_record();
    }

    g_rr_in_record = record;
}

void rr_set_replay(int replay, unsigned long ram_size)
{
    g_rr_in_replay = replay;
    g_ram_size = ram_size;
    printf("ram size=%ld\n", ram_size);
    // printf("set kernel replay = %d\n", g_rr_in_replay);
}

void accel_start_kernel_replay(void){}

void rr_do_replay_cfu(CPUState *cpu)
{
    X86CPU *x86_cpu;
    CPUArchState *env;
    int ret;

    unsigned long cur_len = 0;
    unsigned long cur_src_addr = 0;
    unsigned long cur_dest_addr = 0;
    bool compare_len = false;
    rr_event_log *node;
    bool reordered = false;


    x86_cpu = X86_CPU(cpu);
    env = &x86_cpu->env;

    node = rr_event_log_head;

    if (rr_event_log_head->type != EVENT_TYPE_CFU) {
        // The breakpoint we set in record is actually end of CFU, but in replay we feed
        // the on CFU entry. There might be interrupt or page fault happening during a CFU,
        // which means it is queued before the CFU in the log, so we do this check if the
        // next next event is CFU.
        if (rr_event_log_head->type == EVENT_TYPE_INTERRUPT || rr_event_log_head->type == EVENT_TYPE_EXCEPTION) {
            if (rr_event_log_head->next != NULL && rr_event_log_head->next->type == EVENT_TYPE_CFU) {
                node = rr_event_log_head->next;
                rr_event_log_head->next = rr_event_log_head->next->next;
                reordered = true;
            } else {
                printf("Expected log copy from user, but got %d, ip=0x%lx\n", rr_event_log_head->type, env->eip);
                abort();
            }
        }
    }

    // if (env->eip != STRNCPY_FROM_USER && rr_event_log_head->inst_cnt != cpu->rr_executed_inst) {
    //     printf("Unmatched CPU, current inst cnt=%lu, expected=%lu, actual rip=0x%lx, expected rip=0x%lx\n",
    //            cpu->rr_executed_inst, rr_event_log_head->inst_cnt, env->eip, rr_event_log_head->rip);
    // }

    // if (env->eip != STRNCPY_FROM_USER && env->eip != rr_event_log_head->rip) {
    //     printf("Unexpected RIP 0x%lx, expected 0x%lx\n", env->eip, rr_event_log_head->rip);
    //     abort();
    // }

    replayed_event_num++;

    if (env->eip == GET_FROM_USER) {
        printf("Replayed get_user: %lx, event number=%d\n", node->event.cfu.rdx, replayed_event_num);
        qemu_log("Replayed get_user: %lx, event number=%d\n", node->event.cfu.rdx, replayed_event_num);
        env->regs[R_EDX] = node->event.cfu.rdx;

        if (cpu->rr_executed_inst != node->inst_cnt) {
            printf("Inst unmatched %lu != %lu,  fix it\n", cpu->rr_executed_inst, node->inst_cnt);
            cpu->rr_executed_inst = node->inst_cnt;
        }
    } 
    else if(env->eip == STRLEN_USER) {
        printf("Replayed strlen_user: len=%lu, event number=%d\n", node->event.cfu.len, replayed_event_num);
        qemu_log("Replayed strlen_user: len=%lu, event number=%d\n", node->event.cfu.len, replayed_event_num);
        // len = rr_event_log_head->event.cfu.len;
        env->regs[R_EAX] = node->event.cfu.len;
    } else {
        if (env->eip == COPY_FROM_ITER) {
            // Version 1
            // cur_src_addr = env->regs[R_ECX];
            // cur_dest_addr = env->regs[R_EDI];
            // cur_len = env->regs[R_ESI];

            // Version 2
            cur_src_addr = env->regs[R_ESI];
            cur_dest_addr = env->regs[R_R14];
            cur_len = env->regs[R_EAX];
            compare_len = true;
        } else if (env->eip == COPY_FROM_USER) {
            cur_src_addr = env->regs[R_ESI];
            cur_dest_addr = env->regs[R_EDI];
            cur_len = env->regs[R_EDX];
            compare_len = true;
        } else if (env->eip == COPY_PAGE_FROM_ITER_ATOMIC) {
            cur_src_addr = env->regs[R_ECX];
            cur_dest_addr = env->regs[R_R12]; 
            cur_len = env->regs[R_ESI];
            compare_len = true;
        } else if (env->eip == STRNCPY_FROM_USER) {
            printf("Replayed strncpy: src_addr=0x%lx, dest_addr=0x%lx, len=%lu, event number=%d\n",
                node->event.cfu.src_addr,
                node->event.cfu.dest_addr,
                node->event.cfu.len, replayed_event_num);
            qemu_log("Replayed strncpy: src_addr=0x%lx, dest_addr=0x%lx, len=%lu, event number=%d\n",
                    node->event.cfu.src_addr,
                    node->event.cfu.dest_addr,
                    node->event.cfu.len, replayed_event_num);
            cur_src_addr = env->regs[R_ESI];
            cur_dest_addr = env->regs[R_EDI];
        }

        printf("Replayed CFU[0x%lx], src_addr=0x%lx, dest_addr=0x%lx, len=%lu, logged src_addr=0x%lx, dest_addr=0x%lx, len=%lu, event number=%d\n",
                env->eip, cur_src_addr, cur_dest_addr, cur_len,
                node->event.cfu.src_addr, node->event.cfu.dest_addr,
                node->event.cfu.len, replayed_event_num);

        qemu_log("Replayed CFU[0x%lx], src_addr=0x%lx, dest_addr=0x%lx, len=%ld, logged src_addr=0x%lx, dest_addr=0x%lx, len=%lu, event number=%d\n",
                env->eip, cur_src_addr, cur_dest_addr, cur_len,
                node->event.cfu.src_addr, node->event.cfu.dest_addr,
                node->event.cfu.len, replayed_event_num);

        assert(cur_src_addr == node->event.cfu.src_addr);
        assert(cur_dest_addr == node->event.cfu.dest_addr);

        if (compare_len) {
            assert(cur_len == node->event.cfu.len);
        }
        // if (cpu->rr_executed_inst != rr_event_log_head->inst_cnt) {
        //     printf("Inst unmatched %lu != %lu,  fix it\n", cpu->rr_executed_inst, rr_event_log_head->inst_cnt);
        //     cpu->rr_executed_inst = rr_event_log_head->inst_cnt;
        // }

        node->event.cfu.data[node->event.cfu.len] = 0;
        ret = cpu_memory_rw_debug(cpu, node->event.cfu.src_addr,
                                node->event.cfu.data,
                                node->event.cfu.len + 1, true);
        if (ret < 0) {
            printf("Failed to write to address %lx: %d\n", node->event.cfu.dest_addr, ret);
        } else {
            printf("Write to address 0x%lx len %lu\n",
                    node->event.cfu.src_addr,
                    node->event.cfu.len);
        }
    }

    if (!reordered)
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

    int event_num = event_syscall_num + event_exception_num + event_interrupt_num + \
                    event_io_input_num + event_cfu_num + event_random_num + event_dma_done + 1;

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

        qemu_log("PF exception: %d, cr2=0x%lx, error_code=%d, inst_cnt: %lu, number=%d\n",
               event_record->event.exception.exception_index, event_record->event.exception.cr2,
               event_record->event.exception.error_code,
               event.inst_cnt, event_num);
        event_exception_num++;
        break;

    case EVENT_TYPE_SYSCALL:
        memcpy(&event_record->event.syscall, &event.event.syscall, sizeof(rr_syscall));
        qemu_log("Syscall: %llu, gs_kernel=0x%lx, inst_cnt: %lu, number=%d\n",
                 event_record->event.syscall.regs.rax, event_record->event.syscall.kernel_gsbase,
                 event.inst_cnt, event_num);
        event_syscall_num++;
        break;

     case EVENT_TYPE_IO_IN:
     case EVENT_TYPE_RDTSC:
        memcpy(&event_record->event.io_input, &event.event.io_input, sizeof(rr_io_input));
        qemu_log("IO Input: %lx, rip=0x%lx, inst_cnt: %lu, number=%d\n",
                 event_record->event.io_input.value, event_record->rip, event_record->inst_cnt, event_num);
        event_io_input_num++;
        break;
    case EVENT_TYPE_CFU:
        memcpy(&event_record->event.cfu, &event.event.cfu, sizeof(rr_cfu));
        qemu_log("CFU: src=0x%lx, dest=0x%lx, len=%lu, rip=0x%lx, inst_cnt: %lu, number=%d\n",
                 event_record->event.cfu.src_addr, event_record->event.cfu.dest_addr,
                 event_record->event.cfu.len,
                 event_record->rip, event_record->inst_cnt, event_num);
        event_cfu_num++;
        break;
    case EVENT_TYPE_RANDOM:
        memcpy(&event_record->event.rand, &event.event.rand, sizeof(rr_random));
        qemu_log("Random: buf=0x%lx, len=%lu, rip=0x%lx, inst_cnt: %lu, number=%d\n",
                 event_record->event.rand.buf, event_record->event.rand.len,
                 event_record->rip, event_record->inst_cnt, event_num);
        event_random_num++;
        break;
    case EVENT_TYPE_DMA_DONE:
        qemu_log("DMA Done number=%d, inst_cnt=%lu\n", event_num, event_record->inst_cnt);
        event_dma_done++;
        break;
    default:
        break;
    }

    return event_record;
}

void rr_do_replay_rand(CPUState *cpu)
{
    int ret;

    if (rr_event_log_head->type != EVENT_TYPE_RANDOM) {
        printf("Unexpected random\n");
        qemu_log("Unexpected random\n");
        abort();
    }

    ret = cpu_memory_rw_debug(cpu, rr_event_log_head->event.rand.buf,
                              rr_event_log_head->event.rand.data,
                              rr_event_log_head->event.rand.len, true);

    if (ret < 0) {
        printf("Failed to write to address %lx: %d\n", rr_event_log_head->event.rand.buf, ret);
    } else {
        printf("Write to address 0x%lx len %lu\n",
               rr_event_log_head->event.rand.buf,
               rr_event_log_head->event.rand.len);
    }

    replayed_event_num++;

    printf("Replayed random: buf=0x%lx, len=%lu, event number=%d\n",
           rr_event_log_head->event.rand.buf,
           rr_event_log_head->event.rand.len, replayed_event_num);
    qemu_log("Replayed random: buf=0x%lx, len=%lu, event number=%d\n",
            rr_event_log_head->event.rand.buf,
            rr_event_log_head->event.rand.len, replayed_event_num);

    rr_pop_event_head();
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
    if (rr_event_cur != NULL && event.inst_cnt == rr_event_cur->inst_cnt) {
        printf("Skip repetitive event\n");
        return;
    }

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

void rr_pop_event_head(void) {
    rr_event_log_head = rr_event_log_head->next;
}

rr_event_log *rr_event_log_new(void)
{
    rr_event_log *event = (rr_event_log*)malloc(sizeof(rr_event_log));
    return event;
}

void rr_print_events_stat(void)
{
    printf("=== Event Stats ===\n");

    printf("Interrupt: %d\nSyscall: %d\nException: %d\nCFU: %d\nRandom: %d\nIO Input: %d\n DMA Done: %d\n",
           event_interrupt_num, event_syscall_num, event_exception_num,
           event_cfu_num, event_random_num, event_io_input_num, event_dma_done);

    total_event_number = event_interrupt_num + event_syscall_num + event_exception_num +\
                         event_cfu_num + event_random_num + event_io_input_num + event_dma_done;

    printf("Total Replay Events: %d\n", total_event_number);
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

    printf("Loaded events\n");
    // rr_pop_event_head();
    // rr_pop_event_head();
    // exit(0);
}

__attribute_maybe_unused__ static void rr_clear_redundant_events(CPUState *cpu)
{
    while (rr_event_log_head != NULL && 
           rr_event_log_head->inst_cnt <= cpu->rr_executed_inst) {
        rr_event_log_head = rr_event_log_head->next;
    }
}

void rr_finish_mem_log(void)
{
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        sync_dirty_pages(cpu);
    }

    memory_global_dirty_log_stop(GLOBAL_DIRTY_MIGRATION);

    qemu_log("=== End of Memory Log ===\n\n");
}

void rr_post_record(void)
{
    rr_save_events();
    rr_dma_post_record();
    rr_memlog_post_record();
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
            finish_replay();            
        }

        *interrupt = -1;
        return;
    }

    if (rr_event_log_head->type == EVENT_TYPE_INTERRUPT) {
        if (rr_event_log_head->inst_cnt == cpu->rr_executed_inst) {

            x86_cpu = X86_CPU(cpu);
            env = &x86_cpu->env;
        
            if (env->eip == rr_event_log_head->rip || cpu->last_pc == rr_event_log_head->rip) {
                *interrupt = CPU_INTERRUPT_HARD;
                qemu_log("Ready to replay int request\n");
                cpu->rr_executed_inst++;
            } else {
                printf("Mismatched, interrupt=%d inst number=%lu and rip=0x%lx, actual rip=0x%lx\n", 
                       rr_event_log_head->event.interrupt.lapic.vector, rr_event_log_head->inst_cnt,
                       rr_event_log_head->rip, env->eip);
                abort();
            }
            return;
        }
    }

    *interrupt = -1;
    return;
}

void rr_do_replay_exception(CPUState *cpu)
{
    X86CPU *x86_cpu;
    CPUArchState *env;

    x86_cpu = X86_CPU(cpu);
    env = &x86_cpu->env;

    if (rr_event_log_head->type != EVENT_TYPE_EXCEPTION) {
        printf("rr_do_replay_exception: Unexpected exception: addr=0x%lx\n", env->cr[2]);
        abort();
        // return;
    }

    cpu->exception_index = rr_event_log_head->event.exception.exception_index;

    // printf("Exception error code %d\n", rr_event_log_head->event.exception.error_code);
    printf("Ready to replay exception: %d\n", cpu->exception_index);
    env->error_code = rr_event_log_head->event.exception.error_code;
    env->cr[2] = rr_event_log_head->event.exception.cr2;

    cpu->rr_executed_inst = rr_event_log_head->inst_cnt - 54;
}

void rr_do_replay_exception_end(CPUState *cpu)
{
    X86CPU *x86_cpu;
    CPUArchState *env;

    x86_cpu = X86_CPU(cpu);
    env = &x86_cpu->env;

    cpu->exception_index = 0;

    if (rr_event_log_head->type != EVENT_TYPE_EXCEPTION) {
        printf("rr_do_replay_exception_end: Unexpected exception: addr=0x%lx\n", env->cr[2]);
        abort();
        // return;
    }

    if (rr_event_log_head->event.exception.cr2 != env->cr[2] ) {
        printf("Unmatched page fault current: address=0x%lx error_code=%d, expected: address=0x%lx error_code=%d\n",
                env->cr[2], env->error_code, rr_event_log_head->event.exception.cr2, rr_event_log_head->event.exception.error_code);
        abort();
    } else {
        printf("Expected PF address: 0x%lx\n", env->cr[2]);
    }

    printf("Replayed exception %d, logged: cr2=0x%lx, error_code=%d, current: cr2=0x%lx, error_code=%d, event number=%d\n", 
           rr_event_log_head->event.exception.exception_index,
           rr_event_log_head->event.exception.cr2,
           rr_event_log_head->event.exception.error_code, env->cr[2], env->error_code, replayed_event_num);

    qemu_log("Replayed exception %d, logged: cr2=0x%lx, error_code=%d, current: cr2=0x%lx, error_code=%d, event number=%d\n", 
            rr_event_log_head->event.exception.exception_index,
            rr_event_log_head->event.exception.cr2,
            rr_event_log_head->event.exception.error_code, env->cr[2], env->error_code, replayed_event_num);

    env->regs[R_EAX] = rr_event_log_head->event.exception.regs.rax;
    env->regs[R_EBX] = rr_event_log_head->event.exception.regs.rbx;
    env->regs[R_ECX] = rr_event_log_head->event.exception.regs.rcx;
    env->regs[R_EDX] = rr_event_log_head->event.exception.regs.rdx;
    env->regs[R_EBP] = rr_event_log_head->event.exception.regs.rbp;
    env->regs[R_ESP] = rr_event_log_head->event.exception.regs.rsp;
    env->regs[R_EDI] = rr_event_log_head->event.exception.regs.rdi;
    env->regs[R_ESI] = rr_event_log_head->event.exception.regs.rsi;
    env->regs[R_R8] = rr_event_log_head->event.exception.regs.r8;
    env->regs[R_R9] = rr_event_log_head->event.exception.regs.r9;
    env->regs[R_R10] = rr_event_log_head->event.exception.regs.r10;
    env->regs[R_R11] = rr_event_log_head->event.exception.regs.r11;
    env->regs[R_R12] = rr_event_log_head->event.exception.regs.r12;
    env->regs[R_R13] = rr_event_log_head->event.exception.regs.r13;
    env->regs[R_R14] = rr_event_log_head->event.exception.regs.r14;
    env->regs[R_R15] = rr_event_log_head->event.exception.regs.r15;

    cpu->rr_executed_inst = rr_event_log_head->inst_cnt;
    replayed_event_num++;
    rr_pop_event_head();
}

void rr_do_replay_syscall(CPUState *cpu)
{
    X86CPU *x86_cpu;
    CPUArchState *env;

    if (rr_event_log_head->type != EVENT_TYPE_SYSCALL) {
        printf("Expected event type %d, actual type %d\n", EVENT_TYPE_SYSCALL, rr_event_log_head->type);
        abort();
    }

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

    env->kernelgsbase = rr_event_log_head->event.syscall.kernel_gsbase;
    env->segs[R_GS].base = rr_event_log_head->event.syscall.msr_gsbase;

    replayed_event_num++;
    rr_pop_event_head();

    qemu_log("Replayed syscall=%lu, replayed event number=%d\n", env->regs[R_EAX], replayed_event_num);
    printf("Replayed syscall=%lu, replayed event number=%d\n", env->regs[R_EAX], replayed_event_num);

    qemu_log("[mem_trace] Syscall: %lu\n", env->regs[R_EAX]);

    if (env->regs[R_EAX] == 59) {
        rr_check_breakpoint_start();
    }

}

void rr_do_replay_io_input(CPUState *cpu, unsigned long *input)
{
    X86CPU *x86_cpu;
    CPUArchState *env;

    if (rr_event_log_head->type != EVENT_TYPE_IO_IN) {
        printf("Expected %d event, found %d", EVENT_TYPE_IO_IN, rr_event_log_head->type);
        abort();
    }

    x86_cpu = X86_CPU(cpu);
    env = &x86_cpu->env;

    if (rr_event_log_head->inst_cnt != cpu->rr_executed_inst - 1) {

        if (rr_event_log_head->inst_cnt == cpu->rr_executed_inst || rr_event_log_head->inst_cnt == cpu->rr_executed_inst + 1) {
            cpu->rr_executed_inst = rr_event_log_head->inst_cnt + 1;
        } else {
            printf("Mismatched IO Input, expected inst cnt %lu, found %lu, logged rip= 0x%lx, actual rip=0x%lx\n",
                rr_event_log_head->inst_cnt, cpu->rr_executed_inst, rr_event_log_head->rip, env->eip);
            rr_verify_dirty_mem(cpu);
            abort();
        }
    }

    if (rr_event_log_head->rip != env->eip) {
        printf("Unexpected IO Input RIP, expected 0x%lx, actual 0x%lx\n",
            rr_event_log_head->rip, env->eip);
        abort();
    }

    replayed_event_num++;

    *input = rr_event_log_head->event.io_input.value;
    rr_pop_event_head();

    qemu_log("Replayed io input=0x%lx, replayed event number=%d\n", *input, replayed_event_num);
    printf("Replayed io input=0x%lx, replayed event number=%d\n", *input, replayed_event_num);
}

void rr_do_replay_rdtsc(CPUState *cpu, unsigned long *tsc)
{
    X86CPU *x86_cpu;
    CPUArchState *env;

    if (rr_event_log_head->type != EVENT_TYPE_RDTSC) {
        printf("Expected %d event, found %d", EVENT_TYPE_RDTSC, rr_event_log_head->type);
        abort();
    }
  
    if (rr_event_log_head->inst_cnt != cpu->rr_executed_inst - 1 &&
        rr_event_log_head->inst_cnt != cpu->rr_executed_inst) {
        printf("Mismatched RDTSC, expected inst cnt %lu, found %lu\n",
               rr_event_log_head->inst_cnt, cpu->rr_executed_inst);
        abort();
    }

    x86_cpu = X86_CPU(cpu);
    env = &x86_cpu->env;

    if (rr_event_log_head->rip != env->eip) {
        printf("Unexpected IO Input RIP, expected 0x%lx, actual 0x%lx\n",
            rr_event_log_head->rip, env->eip);
        abort();
    }

    replayed_event_num++;

    *tsc = rr_event_log_head->event.io_input.value;
    rr_pop_event_head();

    qemu_log("Replayed rdtsc=%lx, replayed event number=%d\n", *tsc, replayed_event_num);
    printf("Replayed rdtsc=%lx, replayed event number=%d\n", *tsc, replayed_event_num);
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
            rr_dma_pre_replay();
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
    // int cur_waited = waited;

    // waited = 1;

    return started_replay;
}

void rr_trap(void) {
    return;
}

int count = 0;

__attribute_maybe_unused__ static void hit_point(CPUArchState *env) {
    printf("get %lx\n", env->eip);
}

static void rr_handle_bp(CPUArchState *env)
{}

void rr_check_for_breakpoint(unsigned long addr, CPUState *cpu)
{
    X86CPU *x86_cpu;
    CPUArchState *env;

    if (addr == bp) {
        x86_cpu = X86_CPU(cpu);
        env = &x86_cpu->env;
        rr_handle_bp(env);
    }

    return;
}

void rr_check_breakpoint_start(void)
{
    bt_started = 1;
    return;
}

void rr_gdb_set_stopped(int stopped)
{
    gdb_stopped = stopped;
}


int rr_is_gdb_stopped(void)
{
    return gdb_stopped;
}


void rr_store_op(CPUArchState *env, unsigned long addr)
{
    CPUState *cs = env_cpu(env);
    hwaddr gpa;

    gpa = cpu_get_phys_page_debug(cs, addr & TARGET_PAGE_MASK);

    if (gpa != -1) {
        gpa += (addr & ~TARGET_PAGE_MASK);
        qemu_log("[mem_trace] gpa=0x%lx, rip=0x%lx\n", gpa, env->eip);
    } else {
        qemu_log("[mem_trace] page not mapped\n");
    }
}

void rr_replay_dma_entry(void)
{
    printf("Replaying dma\n");
    rr_replay_next_dma();
}
