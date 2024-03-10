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

rr_event_log* rr_smp_event_log_queues[16];

static int event_syscall_num = 0;
static int event_exception_num = 0;
static int event_interrupt_num = 0;
static int event_io_input_num = 0;
static int event_cfu_num = 0;
static int event_gfu_num = 0;
static int event_random_num = 0;
static int event_dma_done = 0;
static int event_strnlen = 0;
static int event_rdseed_num = 0;

static int started_replay = 0;
static int initialized_replay = 0;

static int replayed_interrupt_num = 0;

static int replayed_event_num = 1;
static int total_event_number = 0;

static bool log_loaded = false;

static int bt_started = 0;
static unsigned long bp = 0xffffffff8108358f;

static int gdb_stopped = 1;

// int64_t replay_start_time = 0;
static unsigned long dirty_page_num = 0;

static void *ivshmem_base_addr = NULL;

static bool kernel_user_access_pf = false;

static void rr_read_shm_events(void);
static void rr_reset_ivshmem(void);

void rr_fake_call(void){return;}


int get_replayed_event_num(void)
{
    return replayed_event_num;
}

void inc_replayed_number(void)
{
    replayed_event_num++;
}

static int get_total_events_num(void)
{
    return event_interrupt_num + event_syscall_num + event_exception_num + \
           event_cfu_num + event_random_num + event_io_input_num + \
           event_dma_done + event_gfu_num + event_strnlen + event_rdseed_num;
}

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
    printf("Removing existing log files: %s\n", kernel_rr_log);
    remove(kernel_rr_log);

    rr_pre_mem_record();
    rr_dma_pre_record();
}

__attribute_maybe_unused__ static bool check_inst_matched_and_fix(CPUState *cpu, rr_event_log *event)
{
    if (cpu->rr_executed_inst != event->inst_cnt) {
        printf("Inst unmatched, current %lu != expected %lu\n", cpu->rr_executed_inst, event->inst_cnt);
        cpu->rr_executed_inst = event->inst_cnt;
        return false;
    }

    return true;
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

int rr_pop_next_event_type(int event_type)
{
    rr_event_log *cur = rr_event_log_head;

    if (cur != NULL && cur->type == event_type)
        rr_pop_event_head();

    while (cur->next != NULL && cur->next->type != event_type) {
        cur = cur->next;
    }

    if (cur->next != NULL) {
        printf("Poped event %d\n", cur->next->type);
        cur->next = cur->next->next;
        return 0;
    } else {
        printf("Not found event %d\n", event_type);

        return -1;
    }
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
        rr_reset_ivshmem();
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


static bool try_reorder(rr_event_log *start_node, int target_type, rr_event_log **target_node) {
    rr_event_log *cur = start_node;
    bool reordered = false;

    while (cur->next != NULL && cur->next->type != target_type) {
        cur = cur->next;
    }
    reordered = true;
    if (cur->next != NULL) {
        *target_node = cur->next;
        cur->next = cur->next->next;
    } else {
        printf("Could not find target event %d\n", target_type);
        abort();
    }

    return reordered;
}

void rr_do_replay_gfu(CPUState *cpu)
{
    X86CPU *x86_cpu;
    CPUArchState *env;
    rr_event_log *node, *replay_node;
    bool reordered = false;

    x86_cpu = X86_CPU(cpu);
    env = &x86_cpu->env;

    node = rr_event_log_head;
    replay_node = node;

    if (node->type != EVENT_TYPE_GFU) {
        if (node->type == EVENT_TYPE_INTERRUPT) {
            reordered = try_reorder(node, EVENT_TYPE_GFU, &replay_node);
        } else {
            printf("Expected log get from user, but got %d, ip=0x%lx\n", rr_event_log_head->type, env->eip);
            // abort();
            cpu->cause_debug = 1;   
            return;
        }
    }

    printf("Replayed get_user: %lx, event number=%d\n", replay_node->event.gfu.val, replayed_event_num);
    qemu_log("Replayed get_user: %lx, event number=%d\n", replay_node->event.gfu.val, replayed_event_num);

    env->regs[R_EDX] = replay_node->event.gfu.val;
    // env->regs[R_EBX] = rr_event_log_head->event.gfu.val;

    // check_inst_matched_and_fix(cpu, rr_event_log_head);
    if (!reordered)
        rr_pop_event_head();
}


void rr_do_replay_strnlen_user(CPUState *cpu)
{
    X86CPU *x86_cpu;
    CPUArchState *env;
    rr_event_log *node;

    node = rr_event_log_head;

    if (node->type != EVENT_TYPE_STRNLEN) {
        printf("Expeced strnlen_user, got %d\n", node->type);
        cpu->cause_debug = true;
        return;
    }

    x86_cpu = X86_CPU(cpu);
    env = &x86_cpu->env;

    printf("Replayed strlen_user: len=%lu, event number=%d\n", node->event.cfu.len, replayed_event_num);
    qemu_log("Replayed strlen_user: len=%lu, event number=%d\n", node->event.cfu.len, replayed_event_num);
    env->regs[R_EBX] = node->event.cfu.len;

    rr_pop_event_head();
}


void rr_do_replay_cfu(CPUState *cpu)
{
    X86CPU *x86_cpu;
    CPUArchState *env;
    int ret;
    rr_event_log *node;
    rr_event_log *cur = rr_event_log_head;
    bool reordered = false;

    x86_cpu = X86_CPU(cpu);
    env = &x86_cpu->env;

    node = rr_event_log_head;
    if (cur->type != EVENT_TYPE_CFU) {
        printf("Current[%d] not CFU, look for next\n", rr_event_log_head->type);
        while (cur->next != NULL && cur->next->type != EVENT_TYPE_CFU) {
            cur = cur->next;
        }

        if (cur->next == NULL) {
            printf("Expected log copy from user, but got %d, ip=0x%lx\n", rr_event_log_head->type, env->eip);
            // abort();
            cpu->cause_debug = 1;
            return;
        }

        if (cur->next->type == EVENT_TYPE_CFU) {
            node = cur->next;
            reordered = true;
        }
    }

    printf("Replayed CFU[0x%lx]: src_addr=0x%lx, dest_addr=0x%lx, len=%lu, event number=%d\n",
            env->eip,
            node->event.cfu.src_addr,
            node->event.cfu.dest_addr,
            node->event.cfu.len, replayed_event_num);
    qemu_log("Replayed CFU[0x%lx]: src_addr=0x%lx, dest_addr=0x%lx, len=%lu, event number=%d\n",
                env->eip,
                node->event.cfu.src_addr,
                node->event.cfu.dest_addr,
                node->event.cfu.len, replayed_event_num);

    unsigned long write_len = node->event.cfu.len;

    if (node->event.cfu.len < 4096) {
        node->event.cfu.data[node->event.cfu.len] = 0;
        write_len++;
    }

    ret = cpu_memory_rw_debug(cpu, node->event.cfu.src_addr,
                            node->event.cfu.data,
                            write_len, true);
    if (ret < 0) {
        printf("Failed to write to address %lx: %d\n", node->event.cfu.src_addr, ret);
        abort();
    } else {
        printf("Write to address 0x%lx len %lu\n",
                node->event.cfu.src_addr,
                node->event.cfu.len);
    }

    if (!reordered)
        rr_pop_event_head();
    else {
        cur->next = cur->next->next;
        replayed_event_num++;
    }

    return;
}

void rr_do_replay_strncpy_from_user(CPUState *cpu)
{
    // The breakpoint we set in record is actually end of CFU, but in replay we feed
    // the on CFU entry. There might be interrupt or page fault happening during a CFU,
    // which means it is queued before the CFU in the log, so we find the next CFU entry
    // to feed in this replayed CFU.
    bool reordered = false;
    rr_event_log *node;
    X86CPU *x86_cpu;
    CPUArchState *env;
    int ret;

    x86_cpu = X86_CPU(cpu);
    env = &x86_cpu->env;

    node = rr_event_log_head;
    rr_event_log *cur = rr_event_log_head;

    if (cur->type != EVENT_TYPE_CFU) {
        printf("Current[%d] not CFU, look for next\n", rr_event_log_head->type);
        while (cur->next != NULL && cur->next->type != EVENT_TYPE_CFU) {
            cur = cur->next;
        }

        if (cur->next == NULL) {
            printf("Expected log copy from user, but got %d, ip=0x%lx\n", rr_event_log_head->type, env->eip);
            // abort();
            cpu->cause_debug = 1;
            return;
        }

        if (cur->next->type == EVENT_TYPE_CFU) {
            node = cur->next;
            reordered = true;
        }
    }

    printf("Replayed strncpy[0x%lx]: src_addr=0x%lx, dest_addr=0x%lx, len=%lu, event number=%d\n",
            env->eip,
            node->event.cfu.src_addr,
            node->event.cfu.dest_addr,
            node->event.cfu.len, replayed_event_num);
    qemu_log("Replayed strncpy[0x%lx]: src_addr=0x%lx, dest_addr=0x%lx, len=%lu, event number=%d\n",
                env->eip,
                node->event.cfu.src_addr,
                node->event.cfu.dest_addr,
                node->event.cfu.len, replayed_event_num);

    if (node->event.cfu.len > 0) {
        node->event.cfu.data[node->event.cfu.len] = 0;
        ret = cpu_memory_rw_debug(cpu, node->event.cfu.src_addr,
                                node->event.cfu.data,
                                node->event.cfu.len + 1, true);
        if (ret < 0) {
            printf("Failed to write to address %lx: %d, len=%lu\n",
                   node->event.cfu.src_addr, ret, node->event.cfu.len);
            if (ret == -1 && !kernel_user_access_pf) {
                kernel_user_access_pf = true;
                printf("Save the strncpy entry for later\n");
                return;
            } else {
                abort();
            }
        } else {
            printf("Write to address 0x%lx len %lu\n",
                    node->event.cfu.src_addr,
                    node->event.cfu.len);
        }
    }

    if (!reordered)
        rr_pop_event_head();
    else {
        cur->next = cur->next->next;
        replayed_event_num++;
    }
}

static void
rr_merge_user_interrupt_of_guest_and_hypervisor(rr_event_log *guest_event, rr_interrupt *guest_interrupt)
{
    rr_event_log *vcpu_event_head = rr_smp_event_log_queues[guest_event->id];

    if (vcpu_event_head == NULL) {
        printf("Could not find corresponding interrupt from hypervisor\n");
        exit(1);
    }

    guest_interrupt->vector = vcpu_event_head->event.interrupt.vector;
    guest_event->inst_cnt = vcpu_event_head->inst_cnt;
    guest_event->rip = vcpu_event_head->rip;
    guest_interrupt->ecx = vcpu_event_head->event.interrupt.ecx;

    rr_smp_event_log_queues[guest_event->id] = vcpu_event_head->next;
}

static rr_event_log *
rr_event_log_new_from_event(rr_event_log event)
{
    rr_event_log *event_record;

    event_record = rr_event_log_new();

    event_record->type = event.type;
    event_record->inst_cnt = event.inst_cnt;
    event_record->rip = event.rip;
    event_record->id = event.id;
    event_record->next = NULL;

    int event_num = get_total_events_num() + 1;

    switch (event.type)
    {
    case EVENT_TYPE_INTERRUPT:
        event_record->inst_cnt = event.inst_cnt;
        memcpy(&event_record->event.interrupt, &event.event.interrupt, sizeof(rr_interrupt));

        qemu_log("User-Interrupt: %d, inst_cnt: %lu, rip=0x%lx, from=%d, cpu_id=%d, number=%d\n",
                 event_record->event.interrupt.vector,
                 event_record->inst_cnt, event_record->rip,
                 event_record->event.interrupt.from, event_record->id, event_num);
        event_interrupt_num++;
        break;
    
    default:
        printf("Unexpected normal event type %d that is not shm", event.type);
        abort();
        return NULL;
    // case EVENT_TYPE_EXCEPTION:
    //     memcpy(&event_record->event.exception, &event.event.exception, sizeof(rr_exception));

    //     qemu_log("PF exception: %d, cr2=0x%lx, error_code=%d, inst_cnt: %lu, number=%d\n",
    //            event_record->event.exception.exception_index, event_record->event.exception.cr2,
    //            event_record->event.exception.error_code,
    //            event_record->inst_cnt, event_num);
    //     event_exception_num++;
    //     break;

    // case EVENT_TYPE_SYSCALL:
    //     memcpy(&event_record->event.syscall, &event.event.syscall, sizeof(rr_syscall));
    //     qemu_log("Syscall: %llu, gs_kernel=0x%lx, cr3=0x%lx, inst_cnt: %lu, number=%d\n",
    //              event_record->event.syscall.regs.rax, event_record->event.syscall.kernel_gsbase,
    //              event.event.syscall.cr3, event_record->inst_cnt, event_num);
    //     event_syscall_num++;
    //     break;

    //  case EVENT_TYPE_IO_IN:
    //     memcpy(&event_record->event.io_input, &event.event.io_input, sizeof(rr_io_input));
    //     qemu_log("IO Input: %lx, rip=0x%lx, inst_cnt: %lu, number=%d\n",
    //              event_record->event.io_input.value, event_record->rip, event_record->inst_cnt, event_num);
    //     event_io_input_num++;
    //     break;
    //  case EVENT_TYPE_RDTSC:
    //     memcpy(&event_record->event.io_input, &event.event.io_input, sizeof(rr_io_input));
    //     qemu_log("RDTSC: %lx, rip=0x%lx, inst_cnt: %lu, number=%d\n",
    //              event_record->event.io_input.value, event_record->rip, event_record->inst_cnt, event_num);
    //     event_io_input_num++;
    //     break;
    // case EVENT_TYPE_GFU:
    //     memcpy(&event_record->event.gfu, &event.event.gfu, sizeof(rr_gfu));
    //     qemu_log("GFU: val=%lu, rip=0x%lx, inst_cnt: %lu, number=%d\n",
    //              event_record->event.gfu.val,
    //              event_record->rip, event_record->inst_cnt, event_num);
    //     event_gfu_num++;
    //     break;
    // case EVENT_TYPE_RDSEED:
    //     memcpy(&event_record->event.gfu, &event.event.gfu, sizeof(rr_gfu));
    //     qemu_log("RDSEED: val=%lu, number=%d\n",
    //              event_record->event.gfu.val, event_num);
    //     event_gfu_num++;
    //     break;
    // case EVENT_TYPE_CFU:
    //     memcpy(&event_record->event.cfu, &event.event.cfu, sizeof(rr_cfu));
    //     qemu_log("CFU: src=0x%lx, dest=0x%lx, len=%lu, rip=0x%lx, inst_cnt: %lu, number=%d\n",
    //              event_record->event.cfu.src_addr, event_record->event.cfu.dest_addr,
    //              event_record->event.cfu.len,
    //              event_record->rip, event_record->inst_cnt, event_num);
    //     event_cfu_num++;
    //     break;
    // case EVENT_TYPE_RANDOM:
    //     memcpy(&event_record->event.rand, &event.event.rand, sizeof(rr_random));
    //     qemu_log("Random: buf=0x%lx, len=%lu, rip=0x%lx, inst_cnt: %lu, number=%d\n",
    //              event_record->event.rand.buf, event_record->event.rand.len,
    //              event_record->rip, event_record->inst_cnt, event_num);
    //     event_random_num++;
    //     break;
    // case EVENT_TYPE_STRNLEN:
    //     memcpy(&event_record->event.cfu, &event.event.cfu, sizeof(rr_cfu));
    //     qemu_log("Strnlen: len=%lu, number=%d\n", event_record->event.cfu.len, event_num);
    //     event_strnlen++;
    //     break;
    // case EVENT_TYPE_DMA_DONE:
    //     qemu_log("DMA Done number=%d, inst_cnt=%lu\n", event_num, event_record->inst_cnt);
    //     event_dma_done++;
    //     break;
    }

    return event_record;
}

static rr_event_log *rr_get_tail(rr_event_log *rr_event)
{
    rr_event_log *tmp_event = rr_event;

    if (tmp_event == NULL)
        return NULL;

    while(tmp_event->next != NULL) {
        tmp_event = tmp_event->next;
    }

    return tmp_event;
}

static rr_event_log *rr_event_log_new_from_event_shm(rr_event_log_guest event)
{
    rr_event_log *event_record;

    event_record = rr_event_log_new();

    event_record->type = event.type;
    event_record->inst_cnt = event.inst_cnt;
    event_record->rip = event.rip;
    event_record->id = event.id;

    int event_num = get_total_events_num() + 1;

    switch (event.type)
    {
    case EVENT_TYPE_INTERRUPT:
        memcpy(&event_record->event.interrupt, &event.event.interrupt, sizeof(rr_interrupt));
        if (event_record->event.interrupt.from == 3) {
            rr_merge_user_interrupt_of_guest_and_hypervisor(event_record, &(event_record->event.interrupt));
        }

        qemu_log("Interrupt: %d, inst_cnt: %lu, rip=0x%lx, from=%d, cpu_id=%d, spin_count=%lu, number=%d\n",
                 event_record->event.interrupt.vector,
                 event_record->inst_cnt, event_record->rip,
                 event_record->event.interrupt.from, event_record->id,
                 event_record->event.interrupt.spin_count, event_num);
        
        event_interrupt_num++;
        break;

    case EVENT_TYPE_EXCEPTION:
        memcpy(&event_record->event.exception, &event.event.exception, sizeof(rr_exception));

        qemu_log("PF exception: %d, cr2=0x%lx, error_code=%d, inst_cnt: %lu, cpu_id=%d, spin_cnt=%lu, number=%d\n",
               event_record->event.exception.exception_index, event_record->event.exception.cr2,
               event_record->event.exception.error_code,
               event_record->inst_cnt, event_record->id,
               event_record->event.exception.spin_count, event_num);
        event_exception_num++;
        break;

    case EVENT_TYPE_SYSCALL:
        memcpy(&event_record->event.syscall, &event.event.syscall, sizeof(rr_syscall));
        qemu_log("Syscall: %llu, gs_kernel=0x%lx, cr3=0x%lx, inst_cnt: %lu, cpu_id=%d, spin_cnt=%lu, number=%d\n",
                 event_record->event.syscall.regs.rax, event_record->event.syscall.kernel_gsbase,
                 event.event.syscall.cr3, event_record->inst_cnt, event_record->id,
                 event_record->event.syscall.spin_count, event_num);
        event_syscall_num++;
        break;

     case EVENT_TYPE_IO_IN:
        memcpy(&event_record->event.io_input, &event.event.io_input, sizeof(rr_io_input));
        qemu_log("IO Input: %lx, rip=0x%lx, inst_cnt: %lu, cpu_id=%d, number=%d\n",
                 event_record->event.io_input.value, event_record->rip, event_record->inst_cnt, event_record->id, event_num);
        event_io_input_num++;
        break;
     case EVENT_TYPE_RDTSC:
        memcpy(&event_record->event.io_input, &event.event.io_input, sizeof(rr_io_input));
        qemu_log("RDTSC: value=%lx, rip=0x%lx, inst_cnt: %lu, cpu_id=%d, number=%d\n",
                 event_record->event.io_input.value, event_record->rip, event_record->inst_cnt, event_record->id, event_num);
        event_io_input_num++;
        break;
    case EVENT_TYPE_GFU:
        memcpy(&event_record->event.gfu, &event.event.gfu, sizeof(rr_gfu));
        qemu_log("GFU: val=%lu, rip=0x%lx, inst_cnt: %lu, cpu_id=%d, number=%d\n",
                 event_record->event.gfu.val,
                 event_record->rip, event_record->inst_cnt, event_record->id, event_num);
        event_gfu_num++;
        break;
    case EVENT_TYPE_CFU:
        memcpy(&event_record->event.cfu, &event.event.cfu, sizeof(rr_cfu));
        qemu_log("CFU: src=0x%lx, dest=0x%lx, len=%lu, rip=0x%lx, inst_cnt: %lu, cpu_id=%d, number=%d\n",
                 event_record->event.cfu.src_addr, event_record->event.cfu.dest_addr,
                 event_record->event.cfu.len,
                 event_record->rip, event_record->inst_cnt, event_record->id, event_num);
        event_cfu_num++;
        break;
    case EVENT_TYPE_RANDOM:
        memcpy(&event_record->event.rand, &event.event.rand, sizeof(rr_random));
        qemu_log("Random: buf=0x%lx, len=%lu, rip=0x%lx, inst_cnt: %lu, cpu_id=%d, number=%d\n",
                 event_record->event.rand.buf, event_record->event.rand.len,
                 event_record->rip, event_record->inst_cnt, event_record->id, event_num);
        event_random_num++;
        break;
    case EVENT_TYPE_STRNLEN:
        memcpy(&event_record->event.cfu, &event.event.cfu, sizeof(rr_cfu));
        qemu_log("Strnlen: len=%lu, cpu_id=%d, number=%d\n",
                 event_record->event.cfu.len, event_record->id, event_num);
        event_strnlen++;
        break;
    case EVENT_TYPE_DMA_DONE:
        qemu_log("DMA Done number=%d, inst_cnt=%lu\n", event_num, event_record->inst_cnt);
        event_dma_done++;
        break;
    case EVENT_TYPE_RDSEED:
        memcpy(&event_record->event.gfu, &event.event.gfu, sizeof(rr_gfu));
        qemu_log("RDSEED: val=%lu\n", event_record->event.gfu.val);
        event_rdseed_num++;
        break;
    case EVENT_TYPE_RELEASE:
        qemu_log("Lock Released: cpu_id=%d\n", event.id);
    default:
        break;
    }

    return event_record;
}

void rr_do_replay_rand(CPUState *cpu, int hypercall)
{
    int ret;
    X86CPU *x86_cpu;
    CPUArchState *env;
    unsigned long buf_addr;

    x86_cpu = X86_CPU(cpu);
    env = &x86_cpu->env;

    if (rr_event_log_head->type != EVENT_TYPE_RANDOM) {
        printf("Unexpected random\n");
        qemu_log("Unexpected random\n");
        abort();
    }

    if (hypercall) {
        buf_addr = rr_event_log_head->event.rand.buf;
        cpu->rr_executed_inst = rr_event_log_head->inst_cnt;

        uint8_t data[1024];

        qemu_log("Random: actual buf=0x%lx, len=%lu, recorded buf=0x%lx, len=%lu\n",
                env->regs[R_EBX], env->regs[R_ECX],
                rr_event_log_head->event.rand.buf, rr_event_log_head->event.rand.len);

        ret = cpu_memory_rw_debug(cpu, env->regs[R_EBX], data, env->regs[R_ECX], false);
        if (ret != 0) {
            qemu_log("Failed to read from random memory\n");
        } else {
            if (memcmp(data, rr_event_log_head->event.rand.data, rr_event_log_head->event.rand.len))
                qemu_log("Random data not equal\n");
            else
                qemu_log("Randoms are equal\n");
        }
    } else {
        buf_addr = env->regs[R_EDI];
    }

    ret = cpu_memory_rw_debug(cpu, buf_addr,
                              rr_event_log_head->event.rand.data,
                              rr_event_log_head->event.rand.len, true);

    if (ret < 0) {
        printf("Failed to write to address %lx: %d\n", rr_event_log_head->event.rand.buf, ret);
    } else {
        printf("Write to address 0x%lx len %lu\n",
               rr_event_log_head->event.rand.buf,
               rr_event_log_head->event.rand.len);
    }

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
    rr_event_log *event_record = rr_event_log_new_from_event(event);
    rr_event_log *tmp_event_cur = rr_get_tail(rr_smp_event_log_queues[event_record->id]);
    
    if (tmp_event_cur == NULL) {
        rr_smp_event_log_queues[event_record->id] = event_record;
    } else {
        tmp_event_cur->next = event_record;
    }
}

static void append_event_shm(rr_event_log_guest event)
{
    rr_event_log *event_record = rr_event_log_new_from_event_shm(event);
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
    replayed_event_num++;
}

rr_event_log *rr_event_log_new(void)
{
    rr_event_log *event = (rr_event_log*)malloc(sizeof(rr_event_log));
    return event;
}

__attribute_maybe_unused__ static rr_event_log_guest *rr_event_log_guest_new(void)
{
    rr_event_log_guest *event = (rr_event_log_guest*)malloc(sizeof(rr_event_log_guest));
    return event;
}

void rr_print_events_stat(void)
{
    printf("=== Event Stats ===\n");

    printf("Interrupt: %d\nSyscall: %d\nException: %d\nCFU: %d\nGFU: %d\nRandom: %d\n"
           "IO Input: %d\nStrnlen: %d\nDMA IO: %d\nRDSEED: %d\n",
           event_interrupt_num, event_syscall_num, event_exception_num,
           event_cfu_num, event_gfu_num, event_random_num, event_io_input_num, event_strnlen,
           event_dma_done, event_rdseed_num);

    total_event_number = get_total_events_num();

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
    for (int i=0; i < 16; i++) {
        rr_smp_event_log_queues[i] = NULL;
    }

    rr_get_vcpu_events();

    rr_read_shm_events();
    rr_save_events();
    rr_dma_post_record();
    rr_memlog_post_record();

    rr_reset_ivshmem();
}

// void rr_pre_replay(void)
// {
//     rr_load_events();
// }

static bool wait_see_next = false;

void rr_replay_interrupt(CPUState *cpu, int *interrupt)
{    
    X86CPU *x86_cpu;
    CPUArchState *env;
    bool mismatched = false;
    bool matched = false;

    if (rr_event_log_head == NULL) {
        if (started_replay) {
            finish_replay();            
        }

        *interrupt = -1;
        return;
    }

    if (rr_event_log_head->type == EVENT_TYPE_INTERRUPT) {
        x86_cpu = X86_CPU(cpu);
        env = &x86_cpu->env;

        if (wait_see_next) {
            if (env->eip == cpu->last_pc) {

            } else {
                if (env->eip == rr_event_log_head->rip) {
                    matched = true;
                } else {
                    mismatched = true;
                }

                wait_see_next = false;
            }
        } else if (rr_event_log_head->inst_cnt == cpu->rr_executed_inst) {
            if (env->eip < 0xBFFFFFFFFFFF) {
                env->eip = rr_event_log_head->rip;
            }

            if (env->eip == rr_event_log_head->rip) {
                matched = true;
            } else {
                wait_see_next = true;
            }
        } else if (cpu->force_interrupt) {
            matched = true;
            cpu->force_interrupt = false;
            // cpu->rr_executed_inst--;
        } else {
            if (rr_event_log_head->inst_cnt == cpu->rr_executed_inst + 1 && env->eip == rr_event_log_head->rip) {
                matched = true;
                cpu->rr_executed_inst++;
            }
        }

        if (matched) {
            cpu->rr_executed_inst--;
            *interrupt = CPU_INTERRUPT_HARD;
            qemu_log("Ready to replay int request\n");
            cpu->rr_executed_inst++;

            return;
        }

        if (mismatched) {
            printf("Mismatched, interrupt=%d inst number=%lu and rip=0x%lx, actual rip=0x%lx\n", 
                    rr_event_log_head->event.interrupt.vector, rr_event_log_head->inst_cnt,
                    rr_event_log_head->rip, env->eip);
            // abort();
            // exit(1);
            cpu->cause_debug = 1;
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
        cpu->cause_debug = 1;
        return;
        // abort();
        // return;
    }

    cpu->exception_index = rr_event_log_head->event.exception.exception_index;

    // printf("Exception error code %d\n", rr_event_log_head->event.exception.error_code);
    printf("Ready to replay exception: %d\n", cpu->exception_index);
    env->error_code = rr_event_log_head->event.exception.error_code;
    env->cr[2] = rr_event_log_head->event.exception.cr2;

    // printf("Replayed exception %d, logged: cr2=0x%lx, error_code=%d, current: cr2=0x%lx, error_code=%d, event number=%d\n", 
    //        rr_event_log_head->event.exception.exception_index,
    //        rr_event_log_head->event.exception.cr2,
    //        rr_event_log_head->event.exception.error_code, env->cr[2], env->error_code, replayed_event_num);

    // qemu_log("Replayed exception %d, logged: cr2=0x%lx, error_code=%d, current: cr2=0x%lx, error_code=%d, event number=%d\n", 
    //         rr_event_log_head->event.exception.exception_index,
    //         rr_event_log_head->event.exception.cr2,
    //         rr_event_log_head->event.exception.error_code, env->cr[2], env->error_code, replayed_event_num);

    // cpu->rr_executed_inst = rr_event_log_head->inst_cnt - 54;
}

void rr_post_replay_exception(CPUState *cpu)
{
    if (!kernel_user_access_pf) {
        return;
    }

    rr_do_replay_strncpy_from_user(cpu);

    kernel_user_access_pf = false;
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
        return;
    }

    if (rr_event_log_head->event.exception.cr2 != env->cr[2] ) {
        printf("Unmatched page fault current: address=0x%lx error_code=%d, expected: address=0x%lx error_code=%d\n",
                env->cr[2], env->error_code, rr_event_log_head->event.exception.cr2, rr_event_log_head->event.exception.error_code);
        // abort();
        return;
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

    // env->regs[R_EAX] = rr_event_log_head->event.exception.regs.rax;
    // env->regs[R_EBX] = rr_event_log_head->event.exception.regs.rbx;
    // env->regs[R_ECX] = rr_event_log_head->event.exception.regs.rcx;
    // env->regs[R_EDX] = rr_event_log_head->event.exception.regs.rdx;
    // env->regs[R_EBP] = rr_event_log_head->event.exception.regs.rbp;
    // env->regs[R_ESP] = rr_event_log_head->event.exception.regs.rsp;
    // env->regs[R_EDI] = rr_event_log_head->event.exception.regs.rdi;
    // env->regs[R_ESI] = rr_event_log_head->event.exception.regs.rsi;
    // env->regs[R_R8] = rr_event_log_head->event.exception.regs.r8;
    // env->regs[R_R9] = rr_event_log_head->event.exception.regs.r9;
    // env->regs[R_R10] = rr_event_log_head->event.exception.regs.r10;
    // env->regs[R_R11] = rr_event_log_head->event.exception.regs.r11;
    // env->regs[R_R12] = rr_event_log_head->event.exception.regs.r12;
    // env->regs[R_R13] = rr_event_log_head->event.exception.regs.r13;
    // env->regs[R_R14] = rr_event_log_head->event.exception.regs.r14;
    // env->regs[R_R15] = rr_event_log_head->event.exception.regs.r15;

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

    // env->kernelgsbase = rr_event_log_head->event.syscall.kernel_gsbase;
    // env->segs[R_GS].base = rr_event_log_head->event.syscall.msr_gsbase;
    env->cr[3] = rr_event_log_head->event.syscall.cr3;

    cpu->rr_executed_inst--;

    qemu_log("Replayed syscall=%lu, inst_cnt=%lu, replayed event number=%d\n",
            env->regs[R_EAX], cpu->rr_executed_inst, replayed_event_num);
    printf("Replayed syscall=%lu, inst_cnt=%lu, replayed event number=%d\n",
           env->regs[R_EAX], cpu->rr_executed_inst, replayed_event_num);

    qemu_log("[mem_trace] Syscall: %lu\n", env->regs[R_EAX]);

    rr_pop_event_head();

    // if (cpu->rr_executed_inst == 114950724) {
    //     cpu->cause_debug = 1;
    // }

    if (env->regs[R_EAX] == 59) {
        rr_check_breakpoint_start();
    }

}

void rr_do_replay_io_input(CPUState *cpu, unsigned long *input)
{
    X86CPU *x86_cpu;
    CPUArchState *env;

    x86_cpu = X86_CPU(cpu);
    env = &x86_cpu->env;

    if (rr_event_log_head->type != EVENT_TYPE_IO_IN) {
        printf("Expected %d event, found %d, rip=0x%lx\n", EVENT_TYPE_IO_IN, rr_event_log_head->type, env->eip);
        qemu_log("Expected %d event, found %d, rip=0x%lx\n", EVENT_TYPE_IO_IN, rr_event_log_head->type, env->eip);
        cpu->cause_debug = 1;
        return;
        // abort();
    }

    if (rr_event_log_head->inst_cnt != cpu->rr_executed_inst) {
        qemu_log("Mismatched IO Input, expected inst cnt %lu, found %lu, rip=0x%lx\n",
               rr_event_log_head->inst_cnt, cpu->rr_executed_inst, rr_event_log_head->rip);
         cpu->rr_executed_inst = rr_event_log_head->inst_cnt;
    }

    if (rr_event_log_head->rip != env->eip) {
        printf("Unexpected IO Input RIP, expected 0x%lx, actual 0x%lx\n",
            rr_event_log_head->rip, env->eip);
        abort();
    }

    *input = rr_event_log_head->event.io_input.value;
    rr_pop_event_head();

    qemu_log("Replayed io input=0x%lx, inst_cnt=%lu, replayed event number=%d\n",
             *input, cpu->rr_executed_inst, replayed_event_num);
    printf("Replayed io input=0x%lx, inst_cnt=%lu, replayed event number=%d\n",
           *input, cpu->rr_executed_inst, replayed_event_num);
}

void rr_do_replay_rdtsc(CPUState *cpu, unsigned long *tsc)
{
    X86CPU *x86_cpu;
    CPUArchState *env;

    if (rr_event_log_head->type != EVENT_TYPE_RDTSC) {
        printf("Expected %d event, found %d", EVENT_TYPE_RDTSC, rr_event_log_head->type);
        qemu_log("Expected %d event, found %d", EVENT_TYPE_RDTSC, rr_event_log_head->type);
        // abort();
        cpu->cause_debug = true;
        return;
    }
  
    x86_cpu = X86_CPU(cpu);
    env = &x86_cpu->env;

    if (rr_event_log_head->rip != env->eip) {
        printf("Unexpected RDTSC RIP, expected 0x%lx, actual 0x%lx\n",
            rr_event_log_head->rip, env->eip);
        abort();
    }

    if (rr_event_log_head->inst_cnt != cpu->rr_executed_inst) {
        qemu_log("Mismatched RDTSC, expected inst cnt %lu, found %lu, rip=0x%lx\n",
               rr_event_log_head->inst_cnt, cpu->rr_executed_inst, env->eip);
        // abort();
        // cpu->cause_debug = 1;
        cpu->rr_executed_inst = rr_event_log_head->inst_cnt;
        // return;

    }

    *tsc = rr_event_log_head->event.io_input.value;
    rr_pop_event_head();

    qemu_log("Replayed rdtsc=%lx, replayed event number=%d\n", *tsc, replayed_event_num);
    printf("Replayed rdtsc=%lx, replayed event number=%d\n", *tsc, replayed_event_num);
}

void rr_do_replay_rdseed(unsigned long *val)
{
    if (rr_event_log_head->type != EVENT_TYPE_RDSEED) {
        qemu_log("Expected rdseed, found %d", rr_event_log_head->type);
        abort();
        // cpu->cause_debug = true;
        return;
    }

    qemu_log("Rplaying rdseed %lu\n", rr_event_log_head->event.gfu.val);

    *val = rr_event_log_head->event.gfu.val;
    rr_pop_event_head();

    qemu_log("Replayed rdseed=%lu, replayed event number=%d\n", *val, replayed_event_num);
    printf("Replayed rdseed=%lu, replayed event number=%d\n", *val, replayed_event_num);
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
    
        *intno = rr_event_log_head->event.interrupt.vector;
        rr_pop_event_head();

        if (!started_replay) {
            started_replay = 1;
        }

        replayed_interrupt_num++;

        qemu_log("Replayed interrupt vector=%d, RIP on replay=0x%lx, inst_cnt=%lu, replayed event number=%d\n",
                 *intno, env->eip, cpu->rr_executed_inst, replayed_event_num);
        printf("Replayed interrupt vecotr=%d, RIP on replay=0x%lx, inst_cnt=%lu, replayed event number=%d\n",
               *intno, env->eip, cpu->rr_executed_inst, replayed_event_num);
        return;
    }

}

uint64_t rr_num_instr_before_next_interrupt(void)
{
    if (rr_event_log_head == NULL) {
        if (!initialized_replay) {
            rr_load_events();
            rr_dma_pre_replay(event_dma_done);
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
    qemu_log("DMA_Replay: Replaying dma\n");
    printf("Replaying dma\n");
    rr_replay_next_dma();
}

static void rr_read_shm_events(void)
{
    rr_event_guest_queue_header *header = (rr_event_guest_queue_header *)ivshmem_base_addr;
    rr_event_log_guest *event;

    for (int i = 0; i < header->current_pos; i++) {
        event = (rr_event_log_guest *)(ivshmem_base_addr + header->header_size + header->entry_size * i);
        append_event_shm(*event);
    }
}

void rr_register_ivshmem(RAMBlock *rb)
{
    ivshmem_base_addr = rb->host;

    rr_event_guest_queue_header *header = (rr_event_guest_queue_header *)ivshmem_base_addr;
    printf("Host addr for shared memory: %p\nHeader info:\ntotal_pos=%u\nrr_endabled=%u\n",
           ivshmem_base_addr, header->total_pos, header->rr_enabled);
}

void rr_ivshmem_set_rr_enabled(int enabled)
{
    rr_event_guest_queue_header *header = (rr_event_guest_queue_header *)ivshmem_base_addr;

    if (enabled)
        printf("enabled in ivshmem\n");
    else
        printf("disabled in ivshmem\n");

    header->rr_enabled = enabled;
}

static void rr_reset_ivshmem(void)
{
    rr_event_guest_queue_header *header = (rr_event_guest_queue_header *)ivshmem_base_addr;

    header->current_pos = 0;
}

unsigned long rr_get_shm_addr(void)
{
    return (unsigned long)ivshmem_base_addr;
}

int rr_inc_inst(CPUState *cpu, unsigned long next_pc)
{
    X86CPU *c = X86_CPU(cpu);
    CPUX86State *env = &c->env;

    if (next_pc != cpu->last_pc || env->regs[R_ECX] == 0) {
        cpu->rr_executed_inst++;
    }

    if ((next_pc == 0xffffffff8148e93b) && env->regs[R_ECX] == 1) {
        cpu->rr_executed_inst++;
    }

    return 0;
}


void rr_handle_kernel_entry(CPUState *cpu, unsigned long bp_addr, unsigned long inst_cnt) {
    X86CPU *c = X86_CPU(cpu);
    CPUX86State *env = &c->env;

    if (kvm_enabled())
        kvm_arch_get_registers(cpu);

    // printf("Step: 0x%lx Inst: %lu, ECX=%lu\n", env->eip, inst_cnt, env->regs[R_ECX]);

    qemu_log("Step: 0x%lx Inst: %lu ECX: %lu\n", env->eip, inst_cnt, env->regs[R_ECX]);

    switch (bp_addr) {
        case SYSCALL_ENTRY:
            qemu_log("check_trace syscall entry[%ld]: %lu. regs: 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx\n",
                     env->regs[R_EAX], inst_cnt,
                     env->regs[R_EBX], env->regs[R_ECX],
                     env->regs[R_EDX], env->regs[R_ESI],
                     env->regs[R_EDX], env->regs[R_ESI],
                     env->regs[R_EDI], env->regs[R_ESP],
                     env->regs[R_EBP]);
            break;
        case SYSCALL_EXIT:
            // qemu_log("check_trace syscall exit: %lu\n", inst_cnt);
            qemu_log("check_trace syscall exit: %lu. regs: 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx\n",
                     inst_cnt, env->regs[R_EAX],
                     env->regs[R_EBX], env->regs[R_ECX],
                     env->regs[R_EDX], env->regs[R_ESI],
                     env->regs[R_EDX], env->regs[R_ESI],
                     env->regs[R_EDI], env->regs[R_ESP],
                     env->regs[R_EBP]);
            break;
        case IRQ_ENTRY:
            // qemu_log("check_trace irq entry: %lu\n", inst_cnt);
            qemu_log("check_trace irq entry: %lu. regs: 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx\n",
                     inst_cnt, env->regs[R_EAX],
                     env->regs[R_EBX], env->regs[R_ECX],
                     env->regs[R_EDX], env->regs[R_ESI],
                     env->regs[R_EDX], env->regs[R_ESI],
                     env->regs[R_EDI], env->regs[R_ESP],
                     env->regs[R_EBP]);
            break;
        case IRQ_EXIT:
            qemu_log("check_trace irq exit: %lu\n", inst_cnt);
            break;
        case RR_RECORD_GFU:
        case RR_GFU_NOCHECK4:
        case RR_GFU_NOCHECK8:
            qemu_log("check_trace gfu[0x%lx] entry: %lu\n", bp_addr, inst_cnt);
            break;
        case RR_RECORD_CFU:
            qemu_log("check_trace cfu entry: %lu\n", inst_cnt);
            break;
        case STRNCPY_FROM_USER:
            qemu_log("check_trace strncpy entry: %lu\n", inst_cnt);
            break;
        case STRNLEN_USER:
            qemu_log("check_trace strnlen entry: %lu\n", inst_cnt);
            break;
        case PF_ASM_EXC:
            qemu_log("check_trace pf entry[0x%lx]: %lu\n", env->cr[2], inst_cnt);
            break;
        case PF_EXEC_END:
            qemu_log("check_trace pf exit: %lu\n", inst_cnt);
            break;
    }
}
