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

#define MAX_CPU_NUM 16

const char *kernel_rr_log = "kernel_rr.log";

__attribute_maybe_unused__ static int g_rr_in_replay = 0;
__attribute_maybe_unused__ static int g_rr_in_record = 0;

unsigned long g_ram_size = 0;

rr_event_log *rr_event_log_head = NULL;
rr_event_log *rr_event_cur = NULL;


rr_event_log* rr_smp_event_log_queues[MAX_CPU_NUM];

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
static int event_release = 0;
static int event_sync_inst = 0;

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

static void *ivshmem_base_addr = NULL;

static bool kernel_user_access_pf = false;

static QemuMutex replay_queue_mutex;
static QemuCond replay_cond;
volatile int current_owner = -1;

static void rr_read_shm_events(void);
static void rr_reset_ivshmem(void);
static void finish_replay(void);
static void rr_log_event(rr_event_log *event_record, int event_num);
static bool rr_replay_is_entry(rr_event_log *event);
static void interrupt_check(rr_event_log *event);

static long syscall_spin_cnt = 0;

void rr_fake_call(void){return;}


static void initialize_replay(void) {
    qemu_mutex_init(&replay_queue_mutex);
    qemu_cond_init(&replay_cond);
}

__attribute_maybe_unused__ void
rr_debug(void) {
    printf("Wake up\n");
}

int replay_cpu_exec_ready(CPUState *cpu)
{
    int ready = 0;

    qemu_mutex_lock(&replay_queue_mutex);
    
    while (1)
    {
        if (rr_event_log_head == NULL) {
            break;
        }

        if (current_owner == cpu->cpu_index) {
            ready = 1;
            break;
        }

        if (rr_event_log_head->id == cpu->cpu_index) {
            ready = 1;
            current_owner = cpu->cpu_index;
            break;
        }

        printf("[%d]Start waiting\n", cpu->cpu_index);

        qemu_cond_wait(&replay_cond, &replay_queue_mutex);

        smp_rmb();

        if (qatomic_mb_read(&cpu->exit_request)) {
            ready = 1;
            printf("CPU Exit \n");
            break;
        }
        printf("CPU %d wake up\n", cpu->cpu_index);
    }

    if (rr_event_log_head == NULL) {
        finish_replay();
    }

    qemu_mutex_unlock(&replay_queue_mutex);

    return ready;
}

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
           event_dma_done + event_gfu_num + event_strnlen + event_rdseed_num + \
           event_release;
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

static void sync_spin_inst_cnt(CPUState *cpu, rr_event_log *event)
{
    long spin_cnt_diff = 0;

    if (event->type == EVENT_TYPE_INTERRUPT) {
        
        spin_cnt_diff = event->event.interrupt.spin_count * 3 - 1;
    }
    else if (event->type == EVENT_TYPE_EXCEPTION) {
        spin_cnt_diff = event->event.exception.spin_count * 3 - 1;
    }

    if (spin_cnt_diff < 0)
        spin_cnt_diff = 0;

    cpu->rr_executed_inst += spin_cnt_diff;
    if (spin_cnt_diff > 0)
        qemu_log("[CPU %d]Synced inst count to %lu\n", cpu->cpu_index, cpu->rr_executed_inst);
}

void sync_syscall_spin_cnt(CPUState *cpu)
{
    if (syscall_spin_cnt != 0) {
        cpu->rr_executed_inst += syscall_spin_cnt * 3 - 1;
    }
    
    if (syscall_spin_cnt > 0)
        qemu_log("Syscall synced inst count to %lu\n", cpu->rr_executed_inst);

    syscall_spin_cnt = 0;
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

    printf("[CPU %d]Replayed get_user: %lx, event number=%d\n",
            cpu->cpu_index, replay_node->event.gfu.val, replayed_event_num);
    qemu_log("[CPU %d]Replayed get_user: %lx, event number=%d\n",
            cpu->cpu_index, replay_node->event.gfu.val, replayed_event_num);

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

    printf("[CPU %d]Replayed strlen_user: len=%lu, event number=%d\n",
            cpu->cpu_index, node->event.cfu.len, replayed_event_num);
    qemu_log("[CPU %d]Replayed strlen_user: len=%lu, event number=%d\n",
            cpu->cpu_index, node->event.cfu.len, replayed_event_num);
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

    printf("[CPU %d]Replayed CFU[0x%lx]: src_addr=0x%lx, dest_addr=0x%lx, len=%lu, event number=%d\n",
            cpu->cpu_index,
            env->eip,
            node->event.cfu.src_addr,
            node->event.cfu.dest_addr,
            node->event.cfu.len, replayed_event_num);
    qemu_log("[CPU %d]Replayed CFU[0x%lx]: src_addr=0x%lx, dest_addr=0x%lx, len=%lu, event number=%d\n",
                cpu->cpu_index,
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

    printf("[CPU %d]Replayed strncpy[0x%lx]: src_addr=0x%lx, dest_addr=0x%lx, len=%lu, event number=%d\n",
            cpu->cpu_index,
            env->eip,
            node->event.cfu.src_addr,
            node->event.cfu.dest_addr,
            node->event.cfu.len, replayed_event_num);
    qemu_log("[CPU %d]Replayed strncpy[0x%lx]: src_addr=0x%lx, dest_addr=0x%lx, len=%lu, event number=%d\n",
                cpu->cpu_index,
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

void rr_do_replay_sync_inst(CPUState *cpu)
{

    qemu_mutex_lock(&replay_queue_mutex);
    if (rr_event_log_head->type != EVENT_TYPE_INST_SYNC) {
        printf("[CPU %d]Unexpected %d expected inst sync\n", cpu->cpu_index, rr_event_log_head->type);
        cpu->cause_debug = true;
        goto finish;
    }
    cpu->rr_executed_inst = rr_event_log_head->inst_cnt;

    printf("[CPU %d]Replayed inst sync to %lu\n", cpu->cpu_index, rr_event_log_head->inst_cnt); 
    qemu_log("[CPU %d]Replayed inst sync to %lu\n", cpu->cpu_index, rr_event_log_head->inst_cnt);

    rr_pop_event_head();

finish:
    qemu_mutex_unlock(&replay_queue_mutex);
}

static void
rr_merge_user_interrupt_of_guest_and_hypervisor(rr_event_log *guest_event, rr_interrupt *guest_interrupt)
{
    rr_event_log *vcpu_event_head = rr_smp_event_log_queues[guest_event->id];

    if (vcpu_event_head == NULL) {
        printf("Could not find corresponding interrupt from hypervisor: cpu_id=%d, spin_count=%lu\n",
               guest_event->id, guest_event->event.interrupt.spin_count);
        // exit(1);
        return;
    }

    guest_interrupt->vector = vcpu_event_head->event.interrupt.vector;
    guest_event->inst_cnt = vcpu_event_head->inst_cnt;
    guest_event->rip = vcpu_event_head->rip;
    guest_interrupt->ecx = vcpu_event_head->event.interrupt.ecx;

    rr_smp_event_log_queues[guest_event->id] = vcpu_event_head->next;
}

static rr_event_log *
rr_event_log_new_from_event(rr_event_log event, int record_mode)
{
    rr_event_log *event_record;
    __attribute_maybe_unused__ int event_num = 0;
    __attribute_maybe_unused__ const char *interrupt_title_name = "Interrupt";

    event_record = rr_event_log_new();

    event_record->type = event.type;
    event_record->inst_cnt = event.inst_cnt;
    event_record->rip = event.rip;
    event_record->id = event.id;
    event_record->next = NULL;

    if (!record_mode) {
        event_num = get_total_events_num() + 1;
    } else {
        interrupt_title_name = "User-Interrupt";
    }

    if (record_mode && event.type != EVENT_TYPE_INTERRUPT) {
        printf("Unexpected normal event type %d that is not shm", event.type);
        abort();
        return NULL;
    }

    switch (event.type)
    {
    case EVENT_TYPE_INTERRUPT:
        event_record->inst_cnt = event.inst_cnt;
        memcpy(&event_record->event.interrupt, &event.event.interrupt, sizeof(rr_interrupt));
        qemu_log("%s event\n", interrupt_title_name);
        if (!record_mode)
            event_interrupt_num++;
        else
            interrupt_check(event_record);
        break;

    case EVENT_TYPE_EXCEPTION:
        memcpy(&event_record->event.exception, &event.event.exception, sizeof(rr_exception));
        event_exception_num++;
        break;

    case EVENT_TYPE_SYSCALL:
        memcpy(&event_record->event.syscall, &event.event.syscall, sizeof(rr_syscall));
        event_syscall_num++;
        break;

     case EVENT_TYPE_IO_IN:
        memcpy(&event_record->event.io_input, &event.event.io_input, sizeof(rr_io_input));
        event_io_input_num++;
        break;
     case EVENT_TYPE_RDTSC:
        memcpy(&event_record->event.io_input, &event.event.io_input, sizeof(rr_io_input));
        event_io_input_num++;
        break;
    case EVENT_TYPE_GFU:
        memcpy(&event_record->event.gfu, &event.event.gfu, sizeof(rr_gfu));
        event_gfu_num++;
        break;
    case EVENT_TYPE_RDSEED:
        memcpy(&event_record->event.gfu, &event.event.gfu, sizeof(rr_gfu));
        event_gfu_num++;
        break;
    case EVENT_TYPE_CFU:
        memcpy(&event_record->event.cfu, &event.event.cfu, sizeof(rr_cfu));
        event_cfu_num++;
        break;
    case EVENT_TYPE_RANDOM:
        memcpy(&event_record->event.rand, &event.event.rand, sizeof(rr_random));
        event_random_num++;
        break;
    case EVENT_TYPE_STRNLEN:
        memcpy(&event_record->event.cfu, &event.event.cfu, sizeof(rr_cfu));
        event_strnlen++;
        break;
    case EVENT_TYPE_DMA_DONE:
        event_dma_done++;
        break;
    case EVENT_TYPE_RELEASE:
        event_release++;
        break;
    case EVENT_TYPE_INST_SYNC:
        event_sync_inst++;
        break;
    default:
        break;
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

static void rr_log_event(rr_event_log *event_record, int event_num) {
    switch (event_record->type)
    {
        case EVENT_TYPE_INTERRUPT:
            qemu_log("Interrupt: %d, inst_cnt: %lu, rip=0x%lx, from=%d, cpu_id=%d, spin_count=%lu, number=%d\n",
                    event_record->event.interrupt.vector,
                    event_record->inst_cnt, event_record->rip,
                    event_record->event.interrupt.from, event_record->id,
                    event_record->event.interrupt.spin_count, event_num);
            
            break;

        case EVENT_TYPE_EXCEPTION:
            qemu_log("PF exception: %d, cr2=0x%lx, error_code=%d, inst_cnt: %lu, cpu_id=%d, spin_cnt=%lu, number=%d\n",
                event_record->event.exception.exception_index, event_record->event.exception.cr2,
                event_record->event.exception.error_code,
                event_record->inst_cnt, event_record->id,
                event_record->event.exception.spin_count, event_num);
            break;

        case EVENT_TYPE_SYSCALL:
            qemu_log("Syscall: %llu, gs_kernel=0x%lx, cr3=0x%lx, inst_cnt: %lu, cpu_id=%d, spin_cnt=%lu, number=%d\n",
                    event_record->event.syscall.regs.rax, event_record->event.syscall.kernel_gsbase,
                    event_record->event.syscall.cr3, event_record->inst_cnt, event_record->id,
                    event_record->event.syscall.spin_count, event_num);
            break;

        case EVENT_TYPE_IO_IN:
            qemu_log("IO Input: %lx, rip=0x%lx, inst_cnt: %lu, cpu_id=%d, number=%d\n",
                    event_record->event.io_input.value, event_record->rip, event_record->inst_cnt, event_record->id, event_num);
            break;
        case EVENT_TYPE_RDTSC:
            qemu_log("RDTSC: value=%lx, rip=0x%lx, inst_cnt: %lu, cpu_id=%d, number=%d\n",
                    event_record->event.io_input.value, event_record->rip, event_record->inst_cnt, event_record->id, event_num);
            break;
        case EVENT_TYPE_GFU:
            qemu_log("GFU: val=%lu, rip=0x%lx, inst_cnt: %lu, cpu_id=%d, number=%d\n",
                    event_record->event.gfu.val,
                    event_record->rip, event_record->inst_cnt, event_record->id, event_num);
            break;
        case EVENT_TYPE_CFU:
            qemu_log("CFU: src=0x%lx, dest=0x%lx, len=%lu, rip=0x%lx, inst_cnt: %lu, cpu_id=%d, number=%d\n",
                    event_record->event.cfu.src_addr, event_record->event.cfu.dest_addr,
                    event_record->event.cfu.len,
                    event_record->rip, event_record->inst_cnt, event_record->id, event_num);
            break;
        case EVENT_TYPE_RANDOM:
            qemu_log("Random: buf=0x%lx, len=%lu, rip=0x%lx, inst_cnt: %lu, cpu_id=%d, number=%d\n",
                    event_record->event.rand.buf, event_record->event.rand.len,
                    event_record->rip, event_record->inst_cnt, event_record->id, event_num);
            break;
        case EVENT_TYPE_STRNLEN:
            qemu_log("Strnlen: len=%lu, cpu_id=%d, number=%d\n",
                    event_record->event.cfu.len, event_record->id, event_num);
            break;
        case EVENT_TYPE_DMA_DONE:
            qemu_log("DMA Done number=%d, inst_cnt=%lu\n", event_num, event_record->inst_cnt);
            break;
        case EVENT_TYPE_RDSEED:
            qemu_log("RDSEED: val=%lu\n", event_record->event.gfu.val);
            break;
        case EVENT_TYPE_RELEASE:
            qemu_log("Lock Released: cpu_id=%d\n", event_record->id);
            break;
        case EVENT_TYPE_INST_SYNC:
            qemu_log("Sync Instructions: cpu_id=%d, inst_cnt=%lu\n", event_record->id, event_record->inst_cnt);
            break;
        default:
            break;
    }

}

static void rr_log_all_events(void)
{
    int num = 1;
    rr_event_log *event = rr_event_log_head;

    while (event != NULL) {
        rr_log_event(event, num);
        event = event->next;
        num++;
    }
}

static rr_event_log *rr_event_log_new_from_event_shm(rr_event_log_guest event)
{
    rr_event_log *event_record;

    event_record = rr_event_log_new();

    event_record->type = event.type;
    event_record->inst_cnt = event.inst_cnt;
    event_record->rip = event.rip;
    event_record->id = event.id;

    __attribute_maybe_unused__ int event_num = get_total_events_num() + 1;

    switch (event.type)
    {
    case EVENT_TYPE_INTERRUPT:
        memcpy(&event_record->event.interrupt, &event.event.interrupt, sizeof(rr_interrupt));
        if (event_record->event.interrupt.from == 3) {
            rr_merge_user_interrupt_of_guest_and_hypervisor(event_record, &(event_record->event.interrupt));
            qemu_log("Merged user interrupt\n");
        }

        interrupt_check(event_record);
        event_interrupt_num++;
        break;

    case EVENT_TYPE_EXCEPTION:
        memcpy(&event_record->event.exception, &event.event.exception, sizeof(rr_exception));
        event_exception_num++;
        break;

    case EVENT_TYPE_SYSCALL:
        memcpy(&event_record->event.syscall, &event.event.syscall, sizeof(rr_syscall));
        event_syscall_num++;
        break;

     case EVENT_TYPE_IO_IN:
        memcpy(&event_record->event.io_input, &event.event.io_input, sizeof(rr_io_input));
        event_io_input_num++;
        break;
     case EVENT_TYPE_RDTSC:
        memcpy(&event_record->event.io_input, &event.event.io_input, sizeof(rr_io_input));
        event_io_input_num++;
        break;
    case EVENT_TYPE_GFU:
        memcpy(&event_record->event.gfu, &event.event.gfu, sizeof(rr_gfu));
        event_gfu_num++;
        break;
    case EVENT_TYPE_CFU:
        memcpy(&event_record->event.cfu, &event.event.cfu, sizeof(rr_cfu));
        event_cfu_num++;
        break;
    case EVENT_TYPE_RANDOM:
        memcpy(&event_record->event.rand, &event.event.rand, sizeof(rr_random));
        event_random_num++;
        break;
    case EVENT_TYPE_STRNLEN:
        memcpy(&event_record->event.cfu, &event.event.cfu, sizeof(rr_cfu));
        event_strnlen++;
        break;
    case EVENT_TYPE_DMA_DONE:
        event_dma_done++;
        break;
    case EVENT_TYPE_RDSEED:
        memcpy(&event_record->event.gfu, &event.event.gfu, sizeof(rr_gfu));
        event_rdseed_num++;
        break;
    case EVENT_TYPE_RELEASE:
        event_release++;
        break;
    case EVENT_TYPE_INST_SYNC:
        event_sync_inst++;
        break;
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

void append_event(rr_event_log event, int is_record)
{
    rr_event_log *event_record = rr_event_log_new_from_event(event, is_record);
    rr_event_log *tmp_event_cur = NULL;
    
    if (is_record) {
        tmp_event_cur = rr_get_tail(rr_smp_event_log_queues[event_record->id]);

        if (tmp_event_cur == NULL) {
            rr_smp_event_log_queues[event_record->id] = event_record;
        } else {
            tmp_event_cur->next = event_record;
        }
    } else {
        if (rr_event_cur == NULL) {
            rr_event_log_head = event_record;
            rr_event_cur = event_record;
        }
        rr_event_cur->next = event_record;
        rr_event_cur = rr_event_cur->next;
        rr_event_cur->next = NULL;
    }

}

static void interrupt_check(rr_event_log *event)
{
    if (rr_event_cur != NULL) {
        if (rr_event_cur->type == EVENT_TYPE_INTERRUPT \
            && event->type == EVENT_TYPE_INTERRUPT \
            && event->id != rr_event_cur->id) {
            printf("Interrupts %d %d from different CPUs are next\n",
                   rr_event_cur->event.interrupt.vector, event->event.interrupt.vector);
        }
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
           "IO Input: %d\nStrnlen: %d\nDMA IO: %d\nRDSEED: %d\nInst Sync: %d\n",
           event_interrupt_num, event_syscall_num, event_exception_num,
           event_cfu_num, event_gfu_num, event_random_num, event_io_input_num, event_strnlen,
           event_dma_done, event_rdseed_num, event_sync_inst);

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
		append_event(loaded_node, 0);
	}

    rr_print_events_stat();
    log_loaded = true;

    rr_log_all_events();

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

__attribute_maybe_unused__ static void 
try_insert_event(int index)
{
    rr_event_log *event = rr_event_log_head;
    rr_event_log *temp1, *temp2 = NULL;

    while (event != NULL && event->next != NULL) {
        if (event->id == index) {
            if (event->inst_cnt < rr_smp_event_log_queues[index]->inst_cnt && \
                rr_smp_event_log_queues[index]->inst_cnt < event->next->inst_cnt) {
                temp1 = event->next;
                temp2 = rr_smp_event_log_queues[index];

                temp2->event.interrupt.spin_count = 0;

                qemu_log("Inserting the missing interrupt %d, inst_cnt=%lu\n",
                            temp2->type, temp2->inst_cnt);

                rr_smp_event_log_queues[index] = rr_smp_event_log_queues[index]->next;
                event->next = temp2;
                event->next->next = temp1;
                return;
            }
        }

        event = event->next;
    }
}

static void rr_record_settle_events(void)
{
    // for (int i=0; i < MAX_CPU_NUM; i++) {
    //     while(rr_smp_event_log_queues[i] != NULL) {
    //         try_insert_event(i);
    //     }
    // }

    rr_log_all_events();

    for (int i = 0; i < MAX_CPU_NUM; i++) {
        if (rr_smp_event_log_queues[i] != NULL) {
            printf("Orphan event from kvm!\n");
            rr_log_event(rr_smp_event_log_queues[i], 0);
            exit(1);
        }
    }
}

void rr_post_record(void)
{
    for (int i=0; i < 16; i++) {
        rr_smp_event_log_queues[i] = NULL;
    }

    rr_get_vcpu_events();

    rr_read_shm_events();

    rr_record_settle_events();

    rr_save_events();
    rr_dma_post_record();
    rr_memlog_post_record();

    rr_reset_ivshmem();
}

// void rr_pre_replay(void)
// {
//     rr_load_events();
// }

__attribute_maybe_unused__ static bool
rr_replay_is_entry(rr_event_log *event)
{
    switch (event->type) {
        case EVENT_TYPE_INTERRUPT:
        case EVENT_TYPE_SYSCALL:
        case EVENT_TYPE_EXCEPTION:
            return true;

        default:
            break;
    }

    return false;
}


static bool wait_see_next = false;

void rr_replay_interrupt(CPUState *cpu, int *interrupt)
{    
    X86CPU *x86_cpu;
    CPUArchState *env;
    bool mismatched = false;
    bool matched = false;

    qemu_mutex_lock(&replay_queue_mutex);

    if (rr_event_log_head == NULL) {
        if (started_replay) {
            finish_replay();            
        }

        *interrupt = -1;
        goto finish;
    }

    x86_cpu = X86_CPU(cpu);
    env = &x86_cpu->env;

    if (cpu->cpu_index != rr_event_log_head->id) {
        goto finish;
    } 

    if (rr_event_log_head->type == EVENT_TYPE_INTERRUPT) {
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

            goto finish;
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

finish:
    qemu_mutex_unlock(&replay_queue_mutex);
    return;
}


void cause_other_cpu_debug(CPUState *cpu)
{
    CPUState *other_cpu;

    CPU_FOREACH(other_cpu) {
        if (other_cpu->cpu_index != cpu->cpu_index) {
            qatomic_mb_set(&other_cpu->exit_request, true);
            qatomic_mb_set(&other_cpu->hit_breakpoint,true);
            other_cpu->stop = false;
            other_cpu->stopped = true;
            smp_wmb();
            qemu_cond_broadcast(&replay_cond);
        }
    }
}


void rr_do_replay_exception(CPUState *cpu)
{
    X86CPU *x86_cpu;
    CPUArchState *env;

    x86_cpu = X86_CPU(cpu);
    env = &x86_cpu->env;

    qemu_mutex_lock(&replay_queue_mutex);

    if (rr_event_log_head->type != EVENT_TYPE_EXCEPTION) {
        printf("rr_do_replay_exception: Unexpected exception: addr=0x%lx\n", env->cr[2]);
        cpu->cause_debug = 1;
        goto finish;
    }

    cpu->exception_index = rr_event_log_head->event.exception.exception_index;

    // printf("Exception error code %d\n", rr_event_log_head->event.exception.error_code);
    printf("Ready to replay exception: %d\n", cpu->exception_index);
    qemu_log("Ready to replay exception: %d\n", cpu->exception_index);
    env->error_code = rr_event_log_head->event.exception.error_code;
    env->cr[2] = rr_event_log_head->event.exception.cr2;

    sync_spin_inst_cnt(cpu, rr_event_log_head);


    // printf("Replayed exception %d, logged: cr2=0x%lx, error_code=%d, current: cr2=0x%lx, error_code=%d, event number=%d\n", 
    //        rr_event_log_head->event.exception.exception_index,
    //        rr_event_log_head->event.exception.cr2,
    //        rr_event_log_head->event.exception.error_code, env->cr[2], env->error_code, replayed_event_num);

    // qemu_log("Replayed exception %d, logged: cr2=0x%lx, error_code=%d, current: cr2=0x%lx, error_code=%d, event number=%d\n", 
    //         rr_event_log_head->event.exception.exception_index,
    //         rr_event_log_head->event.exception.cr2,
    //         rr_event_log_head->event.exception.error_code, env->cr[2], env->error_code, replayed_event_num);

    // cpu->rr_executed_inst = rr_event_log_head->inst_cnt - 54;
finish:
    qemu_mutex_unlock(&replay_queue_mutex);
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

    qemu_mutex_lock(&replay_queue_mutex);

    if (rr_event_log_head->type != EVENT_TYPE_EXCEPTION) {
        printf("rr_do_replay_exception_end: Unexpected exception: addr=0x%lx\n", env->cr[2]);
        abort();
    }

    if (rr_event_log_head->event.exception.cr2 != env->cr[2] ) {
        printf("Unmatched page fault current: address=0x%lx error_code=%d, expected: address=0x%lx error_code=%d\n",
                env->cr[2], env->error_code, rr_event_log_head->event.exception.cr2, rr_event_log_head->event.exception.error_code);
        // abort();
        return;
    } else {
        printf("Expected PF address: 0x%lx\n", env->cr[2]);
    }

    printf("[CPU %d]Replayed exception %d, logged: cr2=0x%lx, error_code=%d, current: cr2=0x%lx, error_code=%d, event number=%d\n", 
           cpu->cpu_index, rr_event_log_head->event.exception.exception_index,
           rr_event_log_head->event.exception.cr2,
           rr_event_log_head->event.exception.error_code, env->cr[2], env->error_code, replayed_event_num);

    qemu_log("[CPU %d]Replayed exception %d, logged: cr2=0x%lx, error_code=%d, current: cr2=0x%lx, error_code=%d, event number=%d\n", 
            cpu->cpu_index, rr_event_log_head->event.exception.exception_index,
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

    qemu_mutex_unlock(&replay_queue_mutex);
}

void rr_do_replay_syscall(CPUState *cpu)
{
    X86CPU *x86_cpu;
    CPUArchState *env;

    qemu_mutex_lock(&replay_queue_mutex);

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
    
    // sync_spin_inst_cnt(cpu, rr_event_log_head);

    syscall_spin_cnt = rr_event_log_head->event.syscall.spin_count;

    qemu_log("[mem_trace] Syscall: %lu\n", env->regs[R_EAX]);

    rr_pop_event_head();

    qemu_mutex_unlock(&replay_queue_mutex);
}

void rr_do_replay_io_input(CPUState *cpu, unsigned long *input)
{
    X86CPU *x86_cpu;
    CPUArchState *env;

    x86_cpu = X86_CPU(cpu);
    env = &x86_cpu->env;

    qemu_mutex_lock(&replay_queue_mutex);

    if (rr_event_log_head->type != EVENT_TYPE_IO_IN) {
        printf("Expected %d event, found %d, rip=0x%lx, cpu_id=%d\n",
                EVENT_TYPE_IO_IN, rr_event_log_head->type, env->eip, cpu->cpu_index);
        qemu_log("Expected %d event, found %d, rip=0x%lx, cpu_id=%d\n",
                 EVENT_TYPE_IO_IN, rr_event_log_head->type, env->eip, cpu->cpu_index);
        cpu->cause_debug = 1;
        goto finish;
    }

    if (rr_event_log_head->inst_cnt != cpu->rr_executed_inst) {
        qemu_log("Mismatched IO Input, expected inst cnt %lu, found %lu, rip=0x%lx\n",
               rr_event_log_head->inst_cnt, cpu->rr_executed_inst, rr_event_log_head->rip);
         cpu->rr_executed_inst = rr_event_log_head->inst_cnt;
    }

    // if (rr_event_log_head->rip != env->eip) {
    //     printf("Unexpected IO Input RIP, expected 0x%lx, actual 0x%lx\n",
    //         rr_event_log_head->rip, env->eip);
    //     abort();
    // }

    *input = rr_event_log_head->event.io_input.value;
    rr_pop_event_head();

    qemu_log("[CPU %d]Replayed io input=0x%lx, inst_cnt=%lu, cpu_id=%d, replayed event number=%d\n",
             cpu->cpu_index, *input, cpu->rr_executed_inst,
             rr_event_log_head->id, replayed_event_num);
    printf("[CPU %d]Replayed io input=0x%lx, inst_cnt=%lu, cpu_id=%d, replayed event number=%d\n",
             cpu->cpu_index, *input, cpu->rr_executed_inst,
             rr_event_log_head->id, replayed_event_num);

finish:
    qemu_mutex_unlock(&replay_queue_mutex);
    return;
}

void rr_do_replay_rdtsc(CPUState *cpu, unsigned long *tsc)
{
    X86CPU *x86_cpu;
    CPUArchState *env;

    qemu_mutex_lock(&replay_queue_mutex);

    if (rr_event_log_head->type != EVENT_TYPE_RDTSC) {
        printf("Expected %d event, found %d", EVENT_TYPE_RDTSC, rr_event_log_head->type);
        qemu_log("Expected %d event, found %d", EVENT_TYPE_RDTSC, rr_event_log_head->type);
        // abort();
        cpu->cause_debug = true;
        goto finish;
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
        cpu->rr_executed_inst = rr_event_log_head->inst_cnt;
    }

    *tsc = rr_event_log_head->event.io_input.value;
    rr_pop_event_head();

    qemu_log("[CPU %d]Replayed rdtsc=%lx, replayed event number=%d\n",
            cpu->cpu_index, *tsc, replayed_event_num);
    printf("[CPU %d]Replayed rdtsc=%lx, replayed event number=%d\n",
           cpu->cpu_index, *tsc, replayed_event_num);

finish:
    qemu_mutex_unlock(&replay_queue_mutex);
    return;
}

void rr_do_replay_release(CPUState *cpu)
{
    qemu_mutex_lock(&replay_queue_mutex);

    if (rr_event_log_head->type != EVENT_TYPE_RELEASE) {
        printf("Unexpected %d, expected lock release, inst_cnt=%lu\n",
               rr_event_log_head->type, cpu->rr_executed_inst);
        cpu->cause_debug = true;
        goto finish;
        // abort();
    }

    rr_pop_event_head();

    qemu_log("[CPU %d]Replayed release, replayed event number=%d\n",
             cpu->cpu_index, replayed_event_num);
    printf("[CPU %d]Replayed release, replayed event number=%d\n",
            cpu->cpu_index, replayed_event_num);

    if (rr_event_log_head != NULL) {
        current_owner = rr_event_log_head->id;
    }

    qemu_cond_broadcast(&replay_cond);

finish:
    qemu_mutex_unlock(&replay_queue_mutex);
}


void rr_do_replay_rdseed(unsigned long *val)
{

    qemu_mutex_lock(&replay_queue_mutex);

    if (rr_event_log_head->type != EVENT_TYPE_RDSEED) {
        qemu_log("Expected rdseed, found %d", rr_event_log_head->type);
        abort();
    }

    qemu_log("Rplaying rdseed %lu\n", rr_event_log_head->event.gfu.val);

    *val = rr_event_log_head->event.gfu.val;
    rr_pop_event_head();

    qemu_log("Replayed rdseed=%lu, replayed event number=%d\n", *val, replayed_event_num);
    printf("Replayed rdseed=%lu, replayed event number=%d\n", *val, replayed_event_num);

    qemu_mutex_unlock(&replay_queue_mutex);
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

        sync_spin_inst_cnt(cpu, rr_event_log_head);
        rr_pop_event_head();

        if (!started_replay) {
            started_replay = 1;
        }

        replayed_interrupt_num++;

        qemu_log("[CPU %d]Replayed interrupt vector=%d, RIP on replay=0x%lx,"\
                 "inst_cnt=%lu, cpu_id=%d, replayed event number=%d\n",
                 cpu->cpu_index, *intno, env->eip, cpu->rr_executed_inst,
                 rr_event_log_head->id, replayed_event_num);
        printf("[CPU %d]Replayed interrupt vector=%d, RIP on replay=0x%lx,"\
                 "inst_cnt=%lu, cpu_id=%d, replayed event number=%d\n",
                 cpu->cpu_index, *intno, env->eip, cpu->rr_executed_inst,
                 rr_event_log_head->id, replayed_event_num);
        return;
    }

}

uint64_t rr_num_instr_before_next_interrupt(void)
{
    if (rr_event_log_head == NULL) {
        if (!initialized_replay) {
            rr_load_events();
            rr_dma_pre_replay(event_dma_done);
            initialize_replay();

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

    // qemu_log("Step: 0x%lx Inst: %lu ECX: %lu\n", env->eip, inst_cnt, env->regs[R_ECX]);

    switch (bp_addr) {
        case SYSCALL_ENTRY:
            qemu_log("[CPU-%d]check_trace syscall entry[%ld]: %lu. regs: 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx\n",
                     cpu->cpu_index, env->regs[R_EAX], inst_cnt,
                     env->regs[R_EBX], env->regs[R_ECX],
                     env->regs[R_EDX], env->regs[R_ESI],
                     env->regs[R_EDX], env->regs[R_ESI],
                     env->regs[R_EDI], env->regs[R_ESP],
                     env->regs[R_EBP]);
            break;
        case SYSCALL_EXIT:
            // qemu_log("check_trace syscall exit: %lu\n", inst_cnt);
            qemu_log("[CPU-%d]check_trace syscall exit: %lu. regs: 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx\n",
                     cpu->cpu_index, inst_cnt, env->regs[R_EAX],
                     env->regs[R_EBX], env->regs[R_ECX],
                     env->regs[R_EDX], env->regs[R_ESI],
                     env->regs[R_EDX], env->regs[R_ESI],
                     env->regs[R_EDI], env->regs[R_ESP],
                     env->regs[R_EBP]);
            break;
        case IRQ_ENTRY:
            // qemu_log("check_trace irq entry: %lu\n", inst_cnt);
            qemu_log("[CPU-%d]check_trace irq entry: %lu. regs: 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx\n",
                     cpu->cpu_index, inst_cnt, env->regs[R_EAX],
                     env->regs[R_EBX], env->regs[R_ECX],
                     env->regs[R_EDX], env->regs[R_ESI],
                     env->regs[R_EDX], env->regs[R_ESI],
                     env->regs[R_EDI], env->regs[R_ESP],
                     env->regs[R_EBP]);
            break;
        case IRQ_EXIT:
            qemu_log("[CPU-%d]check_trace irq exit: %lu\n", cpu->cpu_index, inst_cnt);
            break;
        case RR_RECORD_GFU:
        case RR_GFU_NOCHECK4:
        case RR_GFU_NOCHECK8:
            qemu_log("[CPU-%d]check_trace gfu[0x%lx] entry: %lu\n", cpu->cpu_index, bp_addr, inst_cnt);
            break;
        case RR_RECORD_CFU:
            qemu_log("[CPU-%d]check_trace cfu entry: %lu\n", cpu->cpu_index, inst_cnt);
            break;
        case STRNCPY_FROM_USER:
            qemu_log("[CPU-%d]check_trace strncpy entry: %lu\n", cpu->cpu_index, inst_cnt);
            break;
        case STRNLEN_USER:
            qemu_log("check_trace strnlen entry: %lu\n", inst_cnt);
            break;
        case PF_ASM_EXC:
            qemu_log("[CPU-%d]check_trace pf entry[0x%lx]: %lu\n", cpu->cpu_index, env->cr[2], inst_cnt);
            break;
        case PF_EXEC_END:
            qemu_log("[CPU-%d]check_trace pf exit: %lu\n", cpu->cpu_index, inst_cnt);
            break;
        case RR_HANDLE_SYSCALL:
            qemu_log("[CPU-%d]check_trace handle_syscall: %lu\n", cpu->cpu_index, inst_cnt);
            break;
        case RR_RECORD_SYSCALL:
            qemu_log("[CPU-%d]check_trace record_syscall: %lu\n", cpu->cpu_index, inst_cnt);
            break;
        case RR_HANDLE_IRQ:
            qemu_log("[CPU-%d]check_trace handle_irq: %lu\n", cpu->cpu_index, inst_cnt);
            break;
        case RR_RECORD_IRQ:
            qemu_log("[CPU-%d]check_trace record_irq: %lu\n", cpu->cpu_index, inst_cnt);
            break;
    }
}


CPUState* replay_get_running_cpu(void)
{
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        if (current_owner == cpu->cpu_index) {
            return cpu;
        }
    }

    return NULL;
}
