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
#include "cpu.h"
#include "exec/exec-all.h"
#include "exec/gdbstub.h"

#include <time.h>


#define RESULT_BUF_SIZE 1024

const char *kernel_rr_log = "kernel_rr.log";

__attribute_maybe_unused__ static int g_rr_in_replay = 0;
__attribute_maybe_unused__ static int g_rr_in_record = 0;

unsigned long g_ram_size = 0;

rr_event_log *rr_event_log_head = NULL;
rr_event_log *rr_event_log_start = NULL;
rr_event_log *rr_event_cur = NULL;

rr_event_log* rr_smp_event_log_queues[MAX_CPU_NUM];


typedef struct rr_replay_info_node_t {
    unsigned long cpu_inst_list[MAX_CPU_NUM];
    unsigned long total_inst_cnt;
    int cur_event_num;
    int cur_event_type;
    struct rr_replay_info_node_t *next;
    int lock_owner;
} rr_replay_info_node;

typedef struct rr_replay_info_t {
    FILE *fptr;
    int cur_node_id;
    rr_replay_info_node *replay_info_head;
    unsigned long next_checkpoint_inst;
} rr_replay_info;
static rr_replay_info *replay_info;
static int snapshot_period = 0;
static int restore_snapshot_id = -1;
static const char *replay_snapshot_info_path = "replay-snapshot-info";
static const char *replay_initial_snapshot;


static int event_syscall_num = 0;
static int event_exception_num = 0;
static int event_interrupt_num = 0;
static int event_io_input_num = 0;
static int event_rdtsc_num = 0;
static int event_cfu_num = 0;
static int event_gfu_num = 0;
static int event_pte_num = 0;
static int event_dma_done = 0;
static int event_rdseed_num = 0;
static int event_release = 0;
static int event_sync_inst = 0;

static int started_replay = 0;
static int initialized_replay = 0;

// static int replayed_interrupt_num = 0;

static int replayed_event_num = 0;
static int total_event_number = 0;

__attribute_maybe_unused__ static bool log_loaded = false;

static int bt_started = 0;
static unsigned long bp = 0;

static int gdb_stopped = 1;
static int count_syscall = 0;

// int64_t replay_start_time = 0;
static unsigned long dirty_page_num = 0;

static void *ivshmem_base_addr = NULL;

static bool kernel_user_access_pf = false;
static bool kernel_user_access_pf_cfu = false;
static bool kernel_user_access_pf_strnlen = false;
__attribute_maybe_unused__ static rr_event_log *temp_cfu_event = NULL;

static QemuMutex replay_queue_mutex;
static QemuCond replay_cond;
volatile int current_owner = -1;

static int exit_record = 0;
static int ignore_record = 0;
static int skip_save = 0;

static void rr_read_shm_events(void);
static void rr_reset_ivshmem(void);
static void finish_replay(void);
static void rr_log_event(rr_event_log *event_record, int event_num, int *syscall_table);
static bool rr_replay_is_entry(rr_event_log *event);
static void interrupt_check(rr_event_log *event);
static void rr_read_shm_events_info(void);
static void init_lock_owner(void);
static void rr_sync_header(void);
static void replay_save_snapshot(rr_replay_info *cur_replay_info);
static void replay_save_progress_info(rr_replay_info_node *info_node);

static clock_t replay_start_time;
static long long record_start_time;
static long long record_end_time;
__attribute_maybe_unused__ static bool log_trace = false;

static int cpu_cnt = 0;

static long syscall_spin_cnt = 0;
static unsigned long total_pos = 0;

rr_event_guest_queue_header *queue_header = NULL;
rr_event_guest_queue_header *initial_queue_header = NULL;

typedef struct rr_event_loader_t {
    FILE *fptr;
    unsigned long loaded_events;
    unsigned long total_events;
} rr_event_loader;

static rr_event_loader *event_loader;


#define DEBUG_POINTS_NUM 15
static unsigned long debug_points[DEBUG_POINTS_NUM] = {SYSCALL_ENTRY, RR_SYSRET, PF_ENTRY, RR_IRET, INT_ASM_EXC, INT_ASM_DEBUG, 0xffffffff815ad5a1, 0xffffffff815abdb9};
static int point_index = 6;
static int checkpoint_interval = -1;
static int trace_mode = 0;


void set_skip_save(int skip)
{
    skip_save = skip;
}

void set_trace_mode(int mode)
{
    trace_mode = mode;
}

int get_trace_mode(void)
{
    return trace_mode;
}

void set_checkpoint_interval(int interval)
{
    checkpoint_interval = interval;
}

int get_checkpoint_interval(void)
{
    if (checkpoint_interval == -1) {
        return 1000;
    }

    return checkpoint_interval;
}

static void rr_do_insert_one_breakpoint(CPUState *cpu, unsigned long bp)
{
    int bp_ret;
    bp_ret = kvm_insert_breakpoint(cpu, bp, 1, GDB_BREAKPOINT_SW);
    if (bp_ret > 0) {
        printf("failed to insert bp for 0x%lx: %d\n", bp, bp_ret);
    } else {
        printf("Inserted breakpoints for 0x%lx\n", bp);
    }
}


void rr_do_insert_entry_breakpoints(CPUState *cpu)
{
    for (size_t i = 0; i < point_index; i++) {
        rr_do_insert_one_breakpoint(cpu, debug_points[i]);
    }
}


void rr_do_remove_breakpoints(CPUState *cpu)
{
    for (size_t i = 0; i < DEBUG_POINTS_NUM; i++) {
        if (debug_points[i] > 0)
            kvm_remove_breakpoint(cpu, debug_points[i], 1, GDB_BREAKPOINT_SW);
    }
}


void rr_do_insert_breakpoints(CPUState *cpu)
{
    for (size_t i = point_index; i < DEBUG_POINTS_NUM; i++) {
        if (debug_points[i] > 0)
            rr_do_insert_one_breakpoint(cpu, debug_points[i]);
    }
}

void add_debug_point(unsigned long addr)
{
    debug_points[point_index++] = addr;
}

int addr_in_debug_points(unsigned long addr)
{
    for (size_t i = 0; i < DEBUG_POINTS_NUM; i++) {
        if (debug_points[i] == addr) {
            return 1;
        }
    }
    return 0;
}

int addr_in_extra_debug_points(unsigned long addr)
{
    for (size_t i = point_index; i < DEBUG_POINTS_NUM; i++) {
        if (debug_points[i] == addr) {
            return 1;
        }
    }
    return 0;
}


static long long current_time_in_milliseconds(void) {
    struct timespec spec;
    clock_gettime(CLOCK_REALTIME, &spec);
    return spec.tv_sec * 1000 + spec.tv_nsec / 1e6;
}

/*
This is only called in device mmio context to see if the mmio
is made by kernel.
*/
void check_kernel_access(void)
{
    CPUState *cpu;
    CPUArchState *env;
    X86CPU *x86_cpu;

    CPU_FOREACH(cpu) {
        kvm_arch_get_registers(cpu);
        x86_cpu = X86_CPU(cpu);
        env = &x86_cpu->env;

        if (env->eip > 0xBFFFFFFFFFFF) {
            printf("Kernel access to device on 0x%lx\n", env->eip);
            // abort();
        }
    }
}

void rr_cause_debug(void)
{
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        cpu->cause_debug = 1;
    }
}


void rr_fake_call(void){return;}


void rr_enable_exit_record(void)
{
    exit_record = 1;
}


void rr_enable_ignore_record(void)
{
    ignore_record = 1;
}

int rr_get_ignore_record(void) {
    return ignore_record;
}

static void rr_handle_cpu(CPUArchState *env)
{
    printf("cr0=%lx, eflags=0x%lx\n", env->cr[0], env->eflags);
}

__attribute_maybe_unused__
void dump_cpus_state(void) {
    CPUState *cs;
    CPUArchState *env;
    X86CPU *x86_cpu;

    CPU_FOREACH(cs) {
        printf("CPU#%d:", cs->cpu_index);
        x86_cpu = X86_CPU(cs);
        env = &x86_cpu->env;
        rr_handle_cpu(env);
    }
}

void set_cpu_num(int n)
{
    cpu_cnt = n;
}

int get_cpu_num(void)
{
    return cpu_cnt;
}

void set_initial_replay_snapshot(const char *initial_snapshot)
{
    replay_initial_snapshot = initial_snapshot;
}

void set_restore_snapshot_id(int val)
{
    restore_snapshot_id = val;
}

void rr_restore_snapshot(void)
{
    if (restore_snapshot_id >= 0) {
        restore_snapshot_by_id(restore_snapshot_id);
    }
}

void restore_snapshot_by_id(int ss_id)
{
    char fname[32];
    CPUState *cpu;
    Error *error = NULL;
    int cur_id = 0;
    rr_replay_info_node *node = replay_info->replay_info_head;

    printf("restoring snapshot %d\n", ss_id);

    if (ss_id == 0) {
        strcpy(fname, replay_initial_snapshot);
    } else {
        sprintf(fname, "replay-snapshot.%d", ss_id);
    }

    rr_load_snapshot(fname, &error);
    if (error != NULL) {
        printf("Failed to restore snapshot %s\n", fname);
        abort();
    }

    if (replay_info == NULL) {
        printf("Did not load replay info, skip\n");
        return;
    }

    while(cur_id < ss_id) {
        node = node->next;
        cur_id++;
    }

    printf("Found node with id %d\n", cur_id);

    replayed_event_num = 0;
    rr_event_log_head = rr_event_log_start;
    while(replayed_event_num < node->cur_event_num) {
        rr_pop_event_head();
    }

    CPU_FOREACH(cpu) {
        cpu->rr_executed_inst = node->cpu_inst_list[cpu->cpu_index];
        LOG_MSG("[CPU-%d]Restored snapshot, event number=%d, CPU inst=%lu\n",
                cpu->cpu_index, replayed_event_num, cpu->rr_executed_inst);
    }
    current_owner = node->lock_owner;
}

static void initialize_replay_snapshots(void)
{
    rr_replay_info_node node;
    rr_replay_info_node *new_node, *tail_node = NULL;
    int node_num = 0;
    CPUState *cpu;

    replay_info = (rr_replay_info *)malloc(sizeof(rr_replay_info));
    replay_info->cur_node_id = 1;
    replay_info->replay_info_head = NULL;
    replay_info->fptr = NULL;

    if (snapshot_period > 0) {
        printf("Reinitialize replay snapshot info\n");
        remove(replay_snapshot_info_path);
        replay_info->fptr = fopen(replay_snapshot_info_path, "a");
        replay_info->next_checkpoint_inst = snapshot_period;
    } else {
        replay_info->next_checkpoint_inst = -1;

        replay_info->fptr = fopen(replay_snapshot_info_path, "r");
        if (!replay_info->fptr) {
            printf("Did not find replay snapshot info, skip\n");
            return;
        }

        new_node = (rr_replay_info_node *)malloc(sizeof(rr_replay_info_node));
        CPU_FOREACH(cpu) {
            new_node->cpu_inst_list[cpu->cpu_index] = 0;
        }
        new_node->cur_event_num = 0;
        replay_info->replay_info_head = new_node;
        tail_node = new_node;

        while(fread(&node, sizeof(rr_replay_info_node), 1, replay_info->fptr)) {
            new_node = (rr_replay_info_node *)malloc(sizeof(rr_replay_info_node));
            memcpy(new_node, &node, sizeof(rr_replay_info_node));
            new_node->next = NULL;

            node_num++;
            tail_node->next = new_node;
            tail_node = tail_node->next;
            printf("Loaded %lu, %d type=%d\n", new_node->cpu_inst_list[0], new_node->cur_event_num, new_node->cur_event_type);
        }

        printf("Loaded %d replay snapshot nodes\n", node_num);
    }
}

static void initialize_replay(void) {
    qemu_mutex_init(&replay_queue_mutex);
    qemu_cond_init(&replay_cond);

    initialize_replay_snapshots();

    printf("Initialized replay, cpu number=%d\n", cpu_cnt);
    replay_start_time = clock();
}

__attribute_maybe_unused__ void
rr_debug(void) {
    printf("Wake up\n");
}

int replay_cpu_exec_ready(CPUState *cpu)
{
    int ready = 0;
    X86CPU *x86_cpu;
    CPUArchState *env;

    x86_cpu = X86_CPU(cpu);
    env = &x86_cpu->env;

    qemu_mutex_lock(&replay_queue_mutex);

    while (1)
    {
        if (rr_event_log_head == NULL) {
            if (get_cpu_num() == 1) {
                ready = 1;
            }
            break;
        }

        if (current_owner == cpu->cpu_index) {
            ready = 1;
            break;
        }

        // Nobody is holding the lock and next event is mine
        if (current_owner == -1 && rr_event_log_head->id == cpu->cpu_index) {
            ready = 1;
            current_owner = cpu->cpu_index;
            break;
        }

        LOG_MSG("[%d]Start waiting, current rip=0x%lx\n", cpu->cpu_index, env->eip);

        qemu_mutex_lock(&cpu->work_mutex);
        if (!QSIMPLEQ_EMPTY(&cpu->work_list)) {
            ready = 1;
            qemu_mutex_unlock(&cpu->work_mutex);
            break;
        }
        qemu_mutex_unlock(&cpu->work_mutex);

        qemu_cond_wait(cpu->replay_cond, &replay_queue_mutex);
        qemu_log("CPU %d wake up, current rip=0x%lx\n", cpu->cpu_index, env->eip);

        // smp_rmb();

        if (qatomic_mb_read(&cpu->exit_request)) {
            ready = 1;
            printf("[%d]CPU Exit \n", cpu->cpu_index);
            break;
        }
    }

    if (replay_finished()) {
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
           event_cfu_num + event_io_input_num + event_rdtsc_num + \
           event_dma_done + event_gfu_num + event_rdseed_num + \
           event_release + event_pte_num;
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

    if (cpu_cnt == 1) {
        // Spin cnt sync is only for SMP
        return;
    }

    if (event->type == EVENT_TYPE_INTERRUPT) {
        spin_cnt_diff = event->event.interrupt.spin_count * 3;
    } else if (event->type == EVENT_TYPE_EXCEPTION) {
        qemu_log("spin_cnt_diff=%ld\n", spin_cnt_diff);
        spin_cnt_diff = event->event.exception.spin_count * 3;
    }

    if (spin_cnt_diff < 0)
        spin_cnt_diff = 0;

    cpu->rr_executed_inst += spin_cnt_diff;
    if (spin_cnt_diff > 0)
        qemu_log("[CPU %d]Synced inst count to %lu\n", cpu->cpu_index, cpu->rr_executed_inst);
}

void sync_syscall_spin_cnt(CPUState *cpu)
{
    if (cpu_cnt == 1) {
        // Spin cnt sync is only for SMP
        return;
    }

    if (syscall_spin_cnt != 0) {
        cpu->rr_executed_inst += syscall_spin_cnt * 3;
    }
    
    if (syscall_spin_cnt > 0)
        qemu_log("Syscall synced inst count to %lu\n", cpu->rr_executed_inst);

    syscall_spin_cnt = 0;
}

static void finish_replay(void)
{
    printf("Replay finished\n");
    clock_t end = clock();
    double cpu_time_used = ((double) (end - replay_start_time)) / CLOCKS_PER_SEC;

     printf("Replay executed in %f seconds\n", cpu_time_used);

    rr_print_events_stat();

    rr_memlog_post_replay();
    exit(0);
}

static void pre_record(void) {
    FILE* file = fopen("/dev/shm/record", "w");

    printf("Removing existing log files: %s\n", kernel_rr_log);

    rr_init_checkpoints();
    remove(kernel_rr_log);
    rr_dma_pre_record();
    rr_network_dma_pre_record();
    rr_pre_mem_record();
    fclose(file);

    initial_queue_header = (rr_event_guest_queue_header *)malloc(sizeof(rr_event_guest_queue_header));
    memcpy(initial_queue_header, ivshmem_base_addr, sizeof(rr_event_guest_queue_header));

    printf("Initial queue header enabled=%d\n", initial_queue_header->rr_enabled);

    record_start_time = current_time_in_milliseconds();
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

int rr_inject_exception(CPUState *cpu)
{
    if (rr_event_log_head != NULL && rr_event_log_head->type == EVENT_TYPE_EXCEPTION) {
        if (rr_event_log_head->event.exception.exception_index == DB_VECTOR && \
            cpu->rr_executed_inst == rr_event_log_head->event.exception.inst_cnt)
        {
            return 1;
        }
    }

    return 0;
}

rr_event_log* rr_get_next_event(void)
{
    if (replay_finished()) {
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
        rr_reset_ivshmem();
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


static bool try_reorder(rr_event_log *start_node, int target_type, unsigned long ptr, rr_event_log **target_node) {
    rr_event_log *cur = start_node;
    bool reordered = false;

    while (cur->next != NULL && (cur->next->type != target_type || cur->next->event.gfu.ptr != ptr)) {
        cur = cur->next;
    }
    reordered = true;
    if (cur->next != NULL) {
        *target_node = cur->next;
        cur->next = cur->next->next;
    } else {
        printf("Could not find target event %d, ptr=0x%lx\n", target_type, ptr);
        // abort();
        *target_node = NULL;
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

    if (node->type != EVENT_TYPE_GFU) {
        if (node->type == EVENT_TYPE_INTERRUPT) {
            LOG_MSG("Current not gfu, try to look for next\n");
            reordered = try_reorder(node, EVENT_TYPE_GFU, env->regs[R_ESI], &replay_node);

            if (replay_node == NULL) {
                cpu->cause_debug = 1;
                return;
            }
        } else {
            // while (node != NULL && node->type != EVENT_TYPE_GFU) {
            //     rr_pop_event_head();
            //     node = rr_event_log_head;
            // }

            // if (node == NULL) {
            printf("Expected log get from user, but got %d, ip=0x%lx, inst_cnt=%lu\n", rr_event_log_head->type, env->eip, cpu->rr_executed_inst);
            // abort();
            cpu->cause_debug = 1;
            return;
            // }
        }
    }

    replay_node = node;

    printf("[CPU %d]Replayed get_user[0x%lx]: %lx, event number=%d\n",
            cpu->cpu_index, env->eip, replay_node->event.gfu.val, replayed_event_num);
    qemu_log("[CPU %d]Replayed get_user[0x%lx]: %lx, event number=%d\n",
            cpu->cpu_index, env->eip, replay_node->event.gfu.val, replayed_event_num);

    env->regs[R_EDX] = replay_node->event.gfu.val;
    // env->regs[R_EBX] = rr_event_log_head->event.gfu.val;

    // check_inst_matched_and_fix(cpu, rr_event_log_head);
    if (!reordered)
        rr_pop_event_head();
}

__attribute_maybe_unused__
static void rr_handle_pending_pf_in_cfu(rr_event_log *cur_node)
{
    if (cur_node->next->type == EVENT_TYPE_EXCEPTION) {
        rr_event_log *tmp = cur_node->next;
        cur_node->next = tmp->next;
        tmp->next = cur_node;
        rr_event_log_head = tmp;
    }
}

static void rr_handle_pending_pf_in_cfu2(rr_event_log *cur_node)
{
    temp_cfu_event = cur_node;
}

void rr_do_replay_cfu(CPUState *cpu, int post_exception)
{
    X86CPU *x86_cpu;
    CPUArchState *env;
    int ret;
    rr_event_log *node;
    rr_event_log *cur = rr_event_log_head;
    bool reordered = false;
    bool used_temp = false;

    x86_cpu = X86_CPU(cpu);
    env = &x86_cpu->env;

    node = rr_event_log_head;

    if (temp_cfu_event == NULL || !post_exception) {
        if (cur->type != EVENT_TYPE_CFU) {
            qemu_log("Current[%d] not CFU, look for next\n", rr_event_log_head->type);
            while (cur->next != NULL && (cur->next->type != EVENT_TYPE_CFU || cur->next->event.cfu.src_addr != env->regs[R_EDI])) {
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
    } else {
        node = temp_cfu_event;
        used_temp = true;
        qemu_log("Use cached event src=0x%lx\n", node->event.cfu.src_addr);
    }

    unsigned long write_len = node->event.cfu.len - 1;

    // node->event.cfu.data[node->event.cfu.len - 1] = 0;

    // if ((node->event.cfu.len - 1) % 4096 == 0)
    //     write_len = node->event.cfu.len - 1;

    ret = cpu_memory_rw_debug(cpu, node->event.cfu.src_addr,
                            node->event.cfu.data,
                            write_len, true);
    if (ret < 0) {
        if (ret == -1 && !kernel_user_access_pf_cfu) {
            kernel_user_access_pf_cfu = true;
            qemu_log("Save the cfu entry for later, rip=0x%lx, src=0x%lx\n",
                     env->eip, node->event.cfu.src_addr);
            rr_handle_pending_pf_in_cfu2(node);
            goto finish;
        }

        printf("Failed to write to address %lx: %d\n", node->event.cfu.src_addr, ret);
        // abort();
    } else {
        LOG_MSG("Write to address 0x%lx len %lu\n",
                node->event.cfu.src_addr,
                node->event.cfu.len);
    }

    LOG_MSG("[CPU %d]Replayed CFU[0x%lx]: src_addr=0x%lx, dest_addr=0x%lx, len=%lu, event number=%d\n",
            cpu->cpu_index,
            env->eip,
            node->event.cfu.src_addr,
            node->event.cfu.dest_addr,
            node->event.cfu.len, replayed_event_num);

    if (used_temp) {
        temp_cfu_event = NULL;
        replayed_event_num++;
        return;
    }

finish:
    if (!reordered)
        rr_pop_event_head();
    else {
        cur->next = cur->next->next;
        replayed_event_num++;
    }

    return;
}

static int is_pte_userspace(CPUState *cpu, unsigned long ptr)
{
    int ret;
    unsigned long val;

    ret = cpu_memory_rw_debug(cpu, ptr,
                              &val,
                              sizeof(unsigned long), false);
                            
    if (ret != 0) {
        printf("Failed to read 0x%lx\n", ptr);
        abort();
        return 0;
    }

    return val & (1 << 2);
}


void rr_do_replay_pte(CPUState *cpu)
{
    rr_event_log *node;
    X86CPU *x86_cpu;
    CPUArchState *env;
    int ret;
    bool reordered = false;

    x86_cpu = X86_CPU(cpu);
    env = &x86_cpu->env;

    if (!is_pte_userspace(cpu, env->regs[R_EDI])) {
        // LOG_MSG("Skip non-userspace pte 0x%lx\n", env->regs[R_EDI]);
        return;
    }

    node = rr_event_log_head;

    if (node->type != EVENT_TYPE_PTE) {
        LOG_MSG("Current[%d] not PTE, ptr=0x%lx\n", rr_event_log_head->type, env->regs[R_EDI]);
        reordered = try_reorder(rr_event_log_head, EVENT_TYPE_PTE, env->regs[R_EDI], &node);
    }

    if (node == NULL) {
        cpu->cause_debug = true;
        return;
    }

    if (node->event.gfu.ptr != env->regs[R_EDI]) {
        LOG_MSG("Skip gfu: logged ptr[0x%lx] != actual ptr[0x%lx]\n", rr_event_log_head->event.gfu.ptr, env->regs[R_EDI]);
        return;
    }

    ret = cpu_memory_rw_debug(cpu, node->event.gfu.ptr,
                              &node->event.gfu.val,
                              sizeof(unsigned long), true);
    if (ret < 0) {
        printf("Failed to write to address %lx: %d, val=%lu\n",
                node->event.gfu.ptr, ret, node->event.gfu.val);
        cpu->cause_debug = 1;
        return;
    } else {
        LOG_MSG("[CPU %d]Replayed pte[0x%lx]: pte_addr=0x%lx, val=%lx, event number=%d\n",
                cpu->cpu_index,
                env->eip,
                node->event.gfu.ptr,
                node->event.gfu.val,
                replayed_event_num);
    }

    if (!reordered)
        rr_pop_event_head();
}

void rr_do_replay_io_uring_read_tail(CPUState *cpu)
{
    rr_event_log *node;
    X86CPU *x86_cpu;
    __attribute_maybe_unused__ CPUArchState *env;
    int ret;

    x86_cpu = X86_CPU(cpu);
    env = &x86_cpu->env;

    node = rr_event_log_head;

    if (node->type != EVENT_TYPE_GFU) {
        LOG_MSG("Unexpected event %d, expected GFU\n", node->type);
        cpu->cause_debug = true;
        return;
    }

    ret = cpu_memory_rw_debug(cpu, node->event.gfu.ptr,
                              &node->event.gfu.val,
                              node->event.gfu.size, true);
    if (ret < 0) {
        printf("Failed to write to address %lx: %d, val=%lu\n",
                node->event.gfu.ptr, ret, node->event.gfu.val);
        cpu->cause_debug = 1;
        return;
    } else {
        LOG_MSG("[CPU %d]Replayed io_uring read[0x%lx]: addr=0x%lx, val=%lx, event number=%d\n",
                cpu->cpu_index,
                env->eip,
                node->event.gfu.ptr,
                node->event.gfu.val,
                replayed_event_num);
    }

    rr_pop_event_head();
}

void rr_do_replay_io_uring_read_entry(CPUState *cpu)
{
    rr_event_log *node;
    X86CPU *x86_cpu;
    __attribute_maybe_unused__ CPUArchState *env;
    int ret;

    x86_cpu = X86_CPU(cpu);
    env = &x86_cpu->env;

    node = rr_event_log_head;

    if (node->type != EVENT_TYPE_CFU) {
        LOG_MSG("Unexpected event %d, expected CFU\n", node->type);
        cpu->cause_debug = true;
        return;
    }

    ret = cpu_memory_rw_debug(cpu, node->event.cfu.src_addr,
                              node->event.cfu.data,
                              node->event.cfu.len, true);
    if (ret < 0) {
        printf("Failed to write to address %lx: %d\n",
                node->event.cfu.src_addr, ret);
        cpu->cause_debug = 1;
        return;
    } else {
        LOG_MSG("[CPU %d]Replayed io_uring read entry[0x%lx]: addr=0x%lx, event number=%d\n",
                cpu->cpu_index,
                env->eip,
                node->event.cfu.src_addr,
                replayed_event_num);
    }

    rr_pop_event_head();
}

void rr_do_replay_gfu_call_begin(CPUState *cpu)
{
    rr_event_log *node;
    X86CPU *x86_cpu;
    __attribute_maybe_unused__ CPUArchState *env;
    int ret;

    x86_cpu = X86_CPU(cpu);
    env = &x86_cpu->env;

    if (rr_event_log_head->type != EVENT_TYPE_GFU) {
        LOG_MSG("Current[%d] not GFU\n", rr_event_log_head->type);
        cpu->cause_debug = 1;
        return;
    }

    node = rr_event_log_head;

    ret = cpu_memory_rw_debug(cpu, node->event.gfu.ptr,
                              &node->event.gfu.val,
                              sizeof(unsigned long), true);
    if (ret < 0) {
        printf("Failed to write to address %lx: %d, val=%lu\n",
                node->event.gfu.ptr, ret, node->event.gfu.val);
        cpu->cause_debug = 1;
    } else {
        LOG_MSG("Write to address 0x%lx len %lu\n",
                node->event.gfu.ptr,
                node->event.cfu.len);
        LOG_MSG("[GFU %d]Replayed gfu[0x%lx]: src_addr=0x%lx, val=%lu, event number=%d\n",
                cpu->cpu_index,
                env->eip,
                node->event.gfu.ptr,
                node->event.gfu.val, replayed_event_num);
    }

    rr_pop_event_head();
}


__attribute_maybe_unused__ static bool
is_valid_user_space_address(uint64_t addr) {
    if (addr < 0x0000000000001000)
        return false;

    // Check if the address is in the canonical range (upper 16 bits are sign-extended)
    if ((addr & 0xFFFF000000000000) != 0x0000000000000000 &&
        (addr & 0xFFFF000000000000) != 0xFFFF000000000000) {
        return false;  // Non-canonical address
    }

    // Check if the address is in the user-space range
    return addr <= 0x00007FFFFFFFFFFF;
}


void rr_do_replay_gfu_begin(CPUState *cpu, int post_exception)
{
    // The breakpoint we set in record is actually end of CFU, but in replay we feed
    // the on CFU entry. There might be interrupt or page fault happening during a CFU,
    // which means it is queued before the CFU in the log, so we find the next CFU entry
    // to feed in this replayed CFU.
    rr_event_log *node;
    X86CPU *x86_cpu;
    CPUArchState *env;
    int ret;
    bool used_temp = false;
    bool reordered = false;
    // int unaligned;
    __attribute_maybe_unused__ unsigned long original, diff, base;

    x86_cpu = X86_CPU(cpu);
    env = &x86_cpu->env;

    node = rr_event_log_head;
    rr_event_log *cur = rr_event_log_head;

    if (temp_cfu_event == NULL || !post_exception) {
        if (cur->type != EVENT_TYPE_GFU) {
            LOG_MSG("Current[%d] not GFU, look for next\n", rr_event_log_head->type);
            reordered = try_reorder(cur, EVENT_TYPE_GFU, env->regs[R_EDI], &node);
            if (node == NULL) {
                cpu->cause_debug = 1;
                return;
            }
        }
    } else {
        used_temp = true;
        node = temp_cfu_event;
        LOG_MSG("Use cached event src=0x%lx\n", node->event.gfu.ptr);
    }

    if (env->regs[R_EDI] < node->event.gfu.ptr && env->regs[R_EDI] + sizeof(unsigned long) == node->event.gfu.ptr) {
        LOG_MSG("Skip replay node and wait for next replay\n");
        return;
    }

    if (temp_cfu_event == NULL) {
        if (env->regs[R_EDI] != node->event.gfu.ptr) {
            cpu->cause_debug = 1;
            LOG_MSG("Unexpected gfu 0x%lx!=0x%lx\n", env->regs[R_EDI], node->event.gfu.ptr);
            return;
        }
    }

    ret = cpu_memory_rw_debug(cpu, node->event.gfu.ptr,
                            &node->event.gfu.val,
                            node->event.gfu.size, true);

    if (ret < 0) {
        LOG_MSG("Failed to write to address %lx: %d, val=%lu\n",
                node->event.gfu.ptr, ret, node->event.gfu.val);
        if (ret == -1 && !kernel_user_access_pf) {
            kernel_user_access_pf = true;
            printf("Save the gfu entry for later\n");
            rr_handle_pending_pf_in_cfu2(node);
            goto finish;
        } else {
            return;
        }
    } else {
        LOG_MSG("Write to address 0x%lx len %d\n",
                node->event.gfu.ptr,
                node->event.gfu.size);
        LOG_MSG("[GFU %d]Replayed gfu[0x%lx]: src_addr=0x%lx, dest_addr=%lu, val=%lu, inst=%lu, event number=%d\n",
                cpu->cpu_index,
                env->eip,
                node->event.gfu.ptr,
                env->regs[R_R14],
                node->event.gfu.val, cpu->rr_executed_inst, replayed_event_num);
    }

    if (used_temp) {
        temp_cfu_event = NULL;
        replayed_event_num++;
        return;
    }

finish:
    if (!reordered)
        rr_pop_event_head();
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

    LOG_MSG("[CPU %d]Replayed inst sync to %lu\n", cpu->cpu_index, rr_event_log_head->inst_cnt);

    rr_pop_event_head();

finish:
    qemu_mutex_unlock(&replay_queue_mutex);
}

static void
rr_merge_user_interrupt_of_guest_and_hypervisor(rr_interrupt *guest_interrupt)
{
    rr_event_log *vcpu_event_head = rr_smp_event_log_queues[guest_interrupt->id];

    if (vcpu_event_head == NULL) {
        printf("Could not find corresponding interrupt from hypervisor: cpu_id=%d, spin_count=%lu\n",
              guest_interrupt->id, guest_interrupt->spin_count);
        return;
    }

    guest_interrupt->vector = vcpu_event_head->event.interrupt.vector;
    guest_interrupt->inst_cnt = vcpu_event_head->inst_cnt;
    guest_interrupt->rip = vcpu_event_head->rip;
    guest_interrupt->ecx = vcpu_event_head->event.interrupt.ecx;
    memcpy(&guest_interrupt->regs, &vcpu_event_head->event.interrupt.regs, sizeof(struct kvm_regs));

    rr_smp_event_log_queues[guest_interrupt->id] = vcpu_event_head->next;
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
        // qemu_log("%s event\n", interrupt_title_name);
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
        event_rdtsc_num++;
        break;
    case EVENT_TYPE_PTE:
        memcpy(&event_record->event.gfu, &event.event.gfu, sizeof(rr_gfu));
        event_pte_num++;
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

        event_record->event.cfu.data = event.event.cfu.data;

        event_cfu_num++;
        break;
    case EVENT_TYPE_MMIO:
        memcpy(&event_record->event.io_input, &event.event.io_input, sizeof(rr_io_input));
        event_io_input_num++;
        break;
    case EVENT_TYPE_DMA_DONE: // Unused
        memcpy(&event_record->event.dma_done, &event.event.dma_done, sizeof(rr_dma_done));
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

static void rr_log_event(__attribute_maybe_unused__ rr_event_log *event_record,
                         __attribute_maybe_unused__ int event_num,
                         __attribute_maybe_unused__ int *syscall_table)
{
#ifdef RR_LOG_DEBUG
    switch (event_record->type)
    {
        case EVENT_TYPE_INTERRUPT:
            __attribute_maybe_unused__ rr_interrupt rr_in = event_record->event.interrupt;
            qemu_log("Interrupt: %d, inst_cnt: %lu, rip=0x%lx, from=%d, rcx=0x%llx, cpu_id=%d, spin_count=%lu, number=%d\n",
                    rr_in.vector, rr_in.inst_cnt, rr_in.rip,
                    rr_in.from, rr_in.regs.rcx, rr_in.id, rr_in.spin_count, event_num);
            break;

        case EVENT_TYPE_EXCEPTION:
            qemu_log("Exception: %d, cr2=0x%lx, rip=0x%llx, error_code=%d, cpu_id=%d, spin_cnt=%lu, inst=%lu, number=%d\n",
                event_record->event.exception.exception_index, event_record->event.exception.cr2,
                event_record->event.exception.regs.rip,
                event_record->event.exception.error_code,
                event_record->event.exception.id,
                event_record->event.exception.spin_count,
                event_record->event.exception.inst_cnt, event_num);
            break;

        case EVENT_TYPE_SYSCALL:
            qemu_log("Syscall: %llu, gs_kernel=0x%lx, cr3=0x%lx, cpu_id=%d, spin_cnt=%lu, number=%d\n",
                    event_record->event.syscall.regs.rax, event_record->event.syscall.kernel_gsbase,
                    event_record->event.syscall.cr3, event_record->event.syscall.id,
                    event_record->event.syscall.spin_count, event_num);
            if (count_syscall && syscall_table != NULL)
                syscall_table[event_record->event.syscall.regs.rax] += 1;
            break;

        case EVENT_TYPE_IO_IN:
            qemu_log("IO Input: %lx, rip=0x%lx, inst_cnt: %lu, cpu_id=%d, number=%d\n",
                    event_record->event.io_input.value, event_record->event.io_input.rip,
                    event_record->event.io_input.inst_cnt, event_record->event.io_input.id,
                    event_num);
            break;
        case EVENT_TYPE_RDTSC:
            qemu_log("RDTSC: value=%lx, rip=0x%lx, inst_cnt: %lu, cpu_id=%d, number=%d\n",
                    event_record->event.io_input.value, event_record->event.io_input.rip,
                    event_record->event.io_input.inst_cnt, event_record->event.io_input.id,
                    event_num);
            break;
        case EVENT_TYPE_PTE:
            qemu_log("PTE: val=%lx, ptr=0x%lx, number=%d\n",
                    event_record->event.gfu.val, event_record->event.gfu.ptr, event_num);
            break;
        case EVENT_TYPE_GFU:
            qemu_log("GFU: val=%lu, ptr=0x%lx, size=%d, number=%d\n",
                    event_record->event.gfu.val, event_record->event.gfu.ptr,
                    event_record->event.gfu.size, event_num);
            break;
        case EVENT_TYPE_CFU:
            qemu_log("CFU: src=0x%lx, dest=0x%lx, len=%lu, number=%d\n",
                    event_record->event.cfu.src_addr, event_record->event.cfu.dest_addr,
                    event_record->event.cfu.len, event_num);
            break;
        case EVENT_TYPE_RANDOM:
            qemu_log("Random: buf=0x%lx, len=%lu, number=%d\n",
                    event_record->event.rand.buf, event_record->event.rand.len, event_num);
            break;
        case EVENT_TYPE_STRNLEN:
            qemu_log("Strnlen: len=%lu, src=0x%lx, number=%d\n",
                    event_record->event.cfu.len, event_record->event.cfu.src_addr, event_num);
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
        case EVENT_TYPE_DMA_DONE:
            qemu_log("DMA Done: cpu_id=%d, inst_cnt=%lu\n",
                     event_record->event.dma_done.id,
                     event_record->event.dma_done.inst_cnt);
            break;
        case EVENT_TYPE_MMIO:
            qemu_log("MMIO: cpu_id=%d, val=%lu, rip=0x%lx, inst_cnt=%lu\n",
                     event_record->id,
                     event_record->event.io_input.value,
                     event_record->event.io_input.rip,
                     event_record->event.io_input.inst_cnt);
            break;
        default:
            break;
    }
#endif
}

static void rr_log_all_events(rr_event_log *event)
{
    int num = 1;
    int syscall_table[512] = {0};

    while (event != NULL) {
        rr_log_event(event, num, syscall_table);
        event = event->next;
        num++;
    }

    if (count_syscall) {
        for (int i = 0; i < 512; i++) {
            if (syscall_table[i] > 0)
                printf("syscall %d: %d\n", i, syscall_table[i]);
        }
    }
}

unsigned long replay_get_inst_cnt(void)
{
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        return cpu->rr_executed_inst;
    }

    return 0;
}

void rr_do_replay_rand(CPUState *cpu, int hypercall)
{
    int ret;
    X86CPU *x86_cpu;
    CPUArchState *env;
    unsigned long buf_addr;

    x86_cpu = X86_CPU(cpu);
    env = &x86_cpu->env;

    if (rr_event_log_head->type != EVENT_TYPE_RDSEED) {
        printf("Unexpected random\n");
        qemu_log("Unexpected random\n");
        cpu->cause_debug = 1;
        return;
        // abort();
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

        event_record->next = NULL;
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
        if (event->id != rr_event_cur->id){
            if (rr_event_cur->type == EVENT_TYPE_IO_IN && event->type == EVENT_TYPE_IO_IN)
            {
                printf("Event %lu %lu are suspected interleaved\n",
                    rr_event_cur->event.io_input.value, event->event.io_input.value);
            }
        }
    }
}

static rr_event_log *rr_event_log_new_from_event_shm(void *event, int type, int* copied)
{
    int copied_size = sizeof(rr_event_log_guest);
    rr_event_log *event_record;
    rr_event_log_guest *event_g;

    event_record = rr_event_log_new();

    event_record->type = type;

    __attribute_maybe_unused__ int event_num = get_total_events_num() + 1;

    // printf("type %d\n", type);
    switch (type)
    {
    case EVENT_TYPE_INTERRUPT:
        copied_size = sizeof(rr_interrupt);

        rr_interrupt *in = (rr_interrupt *)event;

        memcpy(&event_record->event.interrupt, in, copied_size);
        if (event_record->event.interrupt.from == 3) {
            // printf("merging interrupt: %d\n", event_num);
            rr_merge_user_interrupt_of_guest_and_hypervisor(&(event_record->event.interrupt));
            qemu_log("Merged user interrupt, inst=%lu\n", event_record->event.interrupt.inst_cnt);
        }

        interrupt_check(event_record);
        event_interrupt_num++;
        break;

    case EVENT_TYPE_EXCEPTION:
        copied_size = sizeof(rr_exception);
        memcpy(&event_record->event.exception, event, copied_size);
        event_exception_num++;
        break;

    case EVENT_TYPE_SYSCALL:
        copied_size = sizeof(rr_syscall);
        memcpy(&event_record->event.syscall, event, copied_size);
        event_syscall_num++;
        break;

    case EVENT_TYPE_IO_IN:
        copied_size = sizeof(rr_io_input);
        memcpy(&event_record->event.io_input, event, copied_size);
        event_io_input_num++;
        break;
    case EVENT_TYPE_RDTSC:
        copied_size = sizeof(rr_io_input);
        memcpy(&event_record->event.io_input, event, copied_size);
        event_rdtsc_num++;
        break;
    case EVENT_TYPE_PTE:
        copied_size = sizeof(rr_gfu);
        memcpy(&event_record->event.gfu, event, copied_size);
        event_pte_num++;
        break;
    case EVENT_TYPE_GFU:
        copied_size = sizeof(rr_gfu);
        memcpy(&event_record->event.gfu, event, copied_size);
        event_gfu_num++;
        break;
    case EVENT_TYPE_CFU:
        copied_size = sizeof(rr_cfu);
        // unsigned char *c = (unsigned char *)(event + sizeof(rr_cfu));
        // printf("cfu addr: %p %s, data %p, offset=%lu\n", c, c, event_record->event.cfu.data, event + sizeof(rr_cfu) - ivshmem_base_addr);

        memcpy(&event_record->event.cfu, event, copied_size);
        int s = event_record->event.cfu.len * sizeof(unsigned char);
        
        event_record->event.cfu.data = (unsigned char *)malloc(s);
        memcpy(event_record->event.cfu.data, (unsigned char *)(event + sizeof(rr_cfu)), s);

        // printf("%s\n", (unsigned char *)event_record->event.cfu.data);
        copied_size += s;

        event_cfu_num++;
        break;
    case EVENT_TYPE_RDSEED:
        copied_size = sizeof(rr_gfu);
        memcpy(&event_record->event.gfu, event, sizeof(rr_gfu));
        event_rdseed_num++;
        break;
    case EVENT_TYPE_MMIO:
        copied_size = sizeof(rr_io_input);
        memcpy(&event_record->event.io_input, event, sizeof(rr_io_input));
        event_io_input_num++;
        break;
    case EVENT_TYPE_RELEASE:
        copied_size = sizeof(rr_event_log_guest);
        event_g = (rr_event_log_guest *)event;
        event_record->id = event_g->id;

        event_release++;
        break;
    case EVENT_TYPE_INST_SYNC:
        copied_size = sizeof(rr_event_log_guest);
        event_g = (rr_event_log_guest *)event;
        event_record->inst_cnt = event_g->inst_cnt;
        event_record->id = event_g->id;
        event_sync_inst++;
        break;
    case EVENT_TYPE_DMA_DONE:
        copied_size = sizeof(rr_dma_done);
        memcpy(&event_record->event.dma_done, event, sizeof(rr_dma_done));
        event_dma_done++;
        if (0 < event_record->event.dma_done.inst_cnt && event_record->event.dma_done.inst_cnt < 100) {
            printf("Strange inst cnt\n");
            abort();
        }
        break;
    default:
        printf("Shm Event: unrecognized event %d\n", type);
        abort();
        break;
    }

    *copied = copied_size;

    return event_record;
}

__attribute_maybe_unused__
static void append_event_shm(void *event, int type)
{
    int copied;

    rr_event_log *event_record = rr_event_log_new_from_event_shm(event, type, &copied);
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
    rr_event_cur = rr_event_log_head;
    rr_event_log_head = rr_event_log_head->next;
    // free(rr_event_cur);
    // rr_event_cur = NULL;

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

__attribute_maybe_unused__
void rr_print_events_stat(void)
{
    FILE *f = fopen("rr-cost.txt", "w");
    char msg[2048];

    total_event_number = get_total_events_num();
    double duration = record_end_time - record_start_time;

    printf("=== Event Stats ===\n");

    sprintf(msg, "Interrupt: %d\nSyscall: %d\nException: %d\nCFU: %d\nGFU: %d\n"
            "IO Input: %d\nRDTSC: %d\nRDSEED: %d\nPTE: %d\nInst Sync: %d\n"
            "DMA Buf Size: %lu\nTotal Replay Events: %d\nTime(s): %.2f\n",
            event_interrupt_num, event_syscall_num, event_exception_num,
            event_cfu_num, event_gfu_num, event_io_input_num, event_rdtsc_num,
            event_rdseed_num, event_pte_num, event_sync_inst, get_dma_buf_size(),
            total_event_number, duration / 1000);

    LOG_MSG("%s", msg);

    fprintf(f, "%s", msg);

    fclose(f);
}

static void persist_event(rr_event_log *event, FILE *fptr)
{
    rr_event_entry_header entry_header = {
        .type = event->type
    };

    fwrite(&entry_header, sizeof(rr_event_entry_header), 1, fptr);

    switch (event->type)
    {
    case EVENT_TYPE_INTERRUPT:
        fwrite(&event->event.interrupt, sizeof(rr_interrupt), 1, fptr);
        break;
    case EVENT_TYPE_EXCEPTION:
        fwrite(&event->event.exception, sizeof(rr_exception), 1, fptr);
        break;
    case EVENT_TYPE_SYSCALL:
        fwrite(&event->event.syscall, sizeof(rr_syscall), 1, fptr);
        break;
    case EVENT_TYPE_IO_IN:
        fwrite(&event->event.io_input, sizeof(rr_io_input), 1, fptr);
        break;
    case EVENT_TYPE_RDTSC:
        fwrite(&event->event.io_input, sizeof(rr_io_input), 1, fptr);
        break;
    case EVENT_TYPE_PTE:
    case EVENT_TYPE_GFU:
        fwrite(&event->event.gfu, sizeof(rr_gfu), 1, fptr);
        break;
    case EVENT_TYPE_CFU:
        fwrite(&event->event.cfu, sizeof(rr_cfu), 1, fptr);
        fwrite(event->event.cfu.data, sizeof(unsigned char) * event->event.cfu.len, 1, fptr);
        break;
    case EVENT_TYPE_RANDOM:
        fwrite(&event->event.rand, sizeof(rr_random), 1, fptr);
        break;
    case EVENT_TYPE_STRNLEN:
        fwrite(&event->event.cfu, sizeof(rr_cfu), 1, fptr);
        break;
    case EVENT_TYPE_RDSEED:
        fwrite(&event->event.gfu, sizeof(rr_gfu), 1, fptr);
        break;
    case EVENT_TYPE_MMIO:
        fwrite(&event->event.io_input, sizeof(rr_io_input), 1, fptr);
        break;
    case EVENT_TYPE_DMA_DONE:
        fwrite(&event->event.dma_done, sizeof(rr_dma_done), 1, fptr);
        break;
    case EVENT_TYPE_RELEASE:
    case EVENT_TYPE_INST_SYNC:
        fwrite(event, sizeof(rr_event_log), 1, fptr);
        break;
    default:
        printf("Persist: Unrecognized event %d\n", event->type);
        abort();
        break;
    }
}

static void load_event(rr_event_log *event, int type, FILE *fptr)
{
    event->type = type;

    switch (type)
    {
    case EVENT_TYPE_INTERRUPT:
        if (!fread(&event->event.interrupt, sizeof(rr_interrupt), 1, fptr))
            goto error;
        event->inst_cnt = event->event.interrupt.inst_cnt;
        event->id = event->event.interrupt.id;
        event->rip = event->event.interrupt.rip;
        break;
    case EVENT_TYPE_EXCEPTION:
        if (!fread(&event->event.exception, sizeof(rr_exception), 1, fptr))
            goto error;
        event->id = event->event.exception.id;
        break;
    case EVENT_TYPE_SYSCALL:
        if (!fread(&event->event.syscall, sizeof(rr_syscall), 1, fptr))
            goto error;
        event->id = event->event.syscall.id;
        break;
    case EVENT_TYPE_IO_IN:
    case EVENT_TYPE_RDTSC:
        if (!fread(&event->event.io_input, sizeof(rr_io_input), 1, fptr))
            goto error;
        event->id = event->event.io_input.id;
        event->inst_cnt = event->event.io_input.inst_cnt;
        event->rip = event->event.io_input.rip;
        break;
    case EVENT_TYPE_PTE:
    case EVENT_TYPE_GFU:
        if (!fread(&event->event.gfu, sizeof(rr_gfu), 1, fptr))
            goto error;

        event->id = event->event.gfu.id;
        break;
    case EVENT_TYPE_CFU:
        if (!fread(&event->event.cfu, sizeof(rr_cfu), 1, fptr))
            goto error;

        event->id = event->event.cfu.id;
        int s = sizeof(unsigned char) * event->event.cfu.len;

        event->event.cfu.data = (unsigned char *)malloc(s); 

        if (!fread(event->event.cfu.data, s, 1, fptr))
            goto error;

        break;
    case EVENT_TYPE_RANDOM:
        if (!fread(&event->event.rand, sizeof(rr_random), 1, fptr))
            goto error;
        
        event->id = event->event.rand.id;
        break;
    case EVENT_TYPE_STRNLEN:
        if (!fread(&event->event.cfu, sizeof(rr_cfu), 1, fptr))
            goto error;
        
        event->id = event->event.cfu.id;
        break;
    case EVENT_TYPE_RDSEED:
        if (!fread(&event->event.gfu, sizeof(rr_gfu), 1, fptr))
            goto error;
        
        event->id = event->event.gfu.id;
        break;
    case EVENT_TYPE_MMIO:
        if (!fread(&event->event.io_input, sizeof(rr_io_input), 1, fptr))
            goto error;

        event->id = 0;
        break;
    case EVENT_TYPE_RELEASE:
    case EVENT_TYPE_INST_SYNC:
        if (!fread(event, sizeof(rr_event_log), 1, fptr))
            goto error;

        break;
    case EVENT_TYPE_DMA_DONE:
        if (!fread(&event->event.dma_done, sizeof(rr_dma_done), 1, fptr))
            goto error;

        event->id = event->event.dma_done.id;
        break;

    default:
        printf("Unrecognized event %d\n", event->type);
        abort();
        break;
    }

    return;
error:
    printf("Failed to read event %d\n", type);
    abort();
}

static void persist_queue_header(rr_event_guest_queue_header *header, FILE *fptr)
{
    fwrite(header, sizeof(rr_event_guest_queue_header), 1, fptr);
}

static FILE* open_or_create(const char* filename) {
    // Try to open existing file
    FILE* file = fopen(filename, "rb+");
    if (file != NULL) {
        return file;
    }

    // If file doesn't exist, create it
    if (errno == ENOENT) {
        // Create file
        file = fopen(filename, "wb+");
        if (file == NULL) {
            fprintf(stderr, "Error creating file %s: %s\n", filename, strerror(errno));
            return NULL;
        }
        
        // Close and reopen in rb+ mode
        fclose(file);
        file = fopen(filename, "rb+");
        if (file == NULL) {
            fprintf(stderr, "Error reopening file %s: %s\n", filename, strerror(errno));
            return NULL;
        }
    } else {
        // Some other error occurred
        fprintf(stderr, "Error opening file %s: %s\n", filename, strerror(errno));
        return NULL;
    }

    return file;
}


static void rr_save_header(void)
{
    FILE *fptr = open_or_create(kernel_rr_log);
    long position;

    rr_sync_header();
    persist_queue_header(initial_queue_header, fptr);

    position = ftell(fptr);
    printf("writing queue header with %u, pos=%ld\n", queue_header->current_pos, position);
    persist_queue_header(queue_header, fptr);

    fclose(fptr);
}

__attribute_maybe_unused__
static void rr_save_events(void)
{
	FILE *fptr; 
	rr_event_log *cur= rr_event_log_head;

    rr_save_header();

    fptr = fopen(kernel_rr_log, "a");

    printf("Start persisted event\n");

    if (fseek(fptr, 0, SEEK_END) != 0) {
        printf("Error seeking to the end of the file\n");
        goto end;
    }

	while (cur != NULL) {
		persist_event(cur, fptr);
        cur = cur->next;
	}

end:
	fclose(fptr);
}

static void rr_load_events(void) {
	__attribute_maybe_unused__ FILE *fptr;;
    rr_event_guest_queue_header header;
    rr_event_log loaded_node;
    rr_event_entry_header entry_header;
    int loaded_event = 0;
    unsigned long max_events = 2000000;

    if (event_loader == NULL) {
        event_loader = (rr_event_loader *)malloc(sizeof(rr_event_loader));
        event_loader->fptr = fopen(kernel_rr_log, "r");
        event_loader->loaded_events = 0;
        event_loader->total_events = 0;

        initial_queue_header = (rr_event_guest_queue_header *)malloc(sizeof(rr_event_guest_queue_header));

        if (!fread(initial_queue_header, sizeof(rr_event_guest_queue_header), 1, event_loader->fptr)) {
            printf("Failed to read headr\n");
            abort();
        }

        if (!fread(&header, sizeof(rr_event_guest_queue_header), 1, event_loader->fptr)) {
            printf("Failed to read headr\n");
            abort();
        }

        event_loader->total_events = header.current_pos - 1;
        printf("Total events to read: %d\n", header.current_pos);
    }

    fptr = event_loader->fptr;

	while(loaded_event < event_loader->total_events && loaded_event < max_events) {
        if (!fread(&entry_header, sizeof(rr_event_entry_header), 1, fptr)) {
            printf("Failed to read event header\n");
            // abort();
            break;
        }

        load_event(&loaded_node, entry_header.type, fptr);
		append_event(loaded_node, 0);
        loaded_event++;
	}

    event_loader->loaded_events += loaded_event;

    rr_print_events_stat();
    rr_log_all_events(rr_event_log_head);
    rr_event_log_start = rr_event_log_head;

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

int replay_finished(void)
{
    if (rr_event_log_head != NULL) {
        return 0;
    }

    if (event_loader->loaded_events < event_loader->total_events) {
        printf("Continue loading more events\n");
        rr_load_events();
        return 0;
    }

    return 1;
}

void try_replay_dma(CPUState *cs, int user_ctx)
{
    rr_dma_entry *head = rr_fetch_next_network_dme_entry(cs->cpu_index);

    while(head != NULL){
        if ((cs->rr_executed_inst == head->inst_cnt - 1 && cs->cpu_index == head->cpu_id)||
            (head->inst_cnt == 0 && replayed_event_num == 0) ||
            (user_ctx && head->inst_cnt == 0 && replayed_event_num + 1 >= head->follow_num) ||
            (head->cpu_id != cs->cpu_index && replayed_event_num + 1 >= head->follow_num)) {
            rr_replay_next_network_dma(cs->cpu_index);
            head = rr_fetch_next_network_dme_entry(cs->cpu_index);
        } else {
            break;
        }
    }

    head = rr_fetch_next_dma_entry(DEV_TYPE_NVME);
    while (head != NULL){
        if ((cs->cpu_index == head->cpu_id && cs->rr_executed_inst == head->inst_cnt) ||
            (user_ctx && head->inst_cnt == 0 && replayed_event_num + 1 >= head->follow_num)
            ||(head->cpu_id != cs->cpu_index && replayed_event_num + 3 >= head->follow_num)
        ) {
            printf("replay next dma user=%d replayed number=%d\n", user_ctx, replayed_event_num);
            rr_replay_next_dma(head->dev_index);
            head = rr_fetch_next_dma_entry(DEV_TYPE_NVME);
        } else {
            break;
        }
    }
}

__attribute_maybe_unused__
static void rr_record_settle_events(void)
{
    // for (int i=0; i < MAX_CPU_NUM; i++) {
    //     while(rr_smp_event_log_queues[i] != NULL) {
    //         try_insert_event(i);
    //     }
    // }
    rr_event_log *event = NULL;
    rr_log_all_events(rr_event_log_head);

    for (int i = 0; i < MAX_CPU_NUM; i++) {
        if (rr_smp_event_log_queues[i] != NULL) {
            LOG_MSG("Orphan event from kvm on cpu %d!\n", i);

            event = rr_smp_event_log_queues[i];

            while (event != NULL) {
                rr_log_event(event, 0, NULL);
                event = event->next;
            }

            // exit(1);
        }
    }
}

void rr_get_result(void)
{
    unsigned long result_buffer = 0;
    int ret;
    CPUState *cpu;
    char buffer[RESULT_BUF_SIZE];
    remove("rr-result.txt");
    FILE *f = fopen("rr-result.txt", "w");

    result_buffer = rr_get_result_buffer();
    printf("Result buffer 0x%lx\n", result_buffer);

    CPU_FOREACH(cpu) {
        ret = cpu_memory_rw_debug(cpu, result_buffer, &buffer, RESULT_BUF_SIZE, false);

        fprintf(f, "%s", buffer);

        if (ret == 0) {
            printf("Buffer: %s\n", buffer);
            qemu_log("%s\n", buffer);
            break;
        }
    }

    fclose(f);

    if (!rr_in_record()) {
        if (exit_record)
            exit(10);
    }
}

static void rr_sync_header(void)
{
    rr_event_guest_queue_header *header = (rr_event_guest_queue_header *)ivshmem_base_addr;

    if (queue_header == NULL)
        queue_header = (rr_event_guest_queue_header*)malloc(sizeof(rr_event_guest_queue_header));

    memcpy(queue_header, header, sizeof(rr_event_guest_queue_header));

    queue_header->current_pos += total_pos;
    printf("synced queue header, current_pos=%u\n", queue_header->current_pos);
}

void rr_post_record(void)
{
    record_end_time = current_time_in_milliseconds();

    for (int i=0; i < 16; i++) {
        rr_smp_event_log_queues[i] = NULL;
    }

    rr_get_vcpu_events();

    rr_read_shm_events_info();

    printf("Getting result\n");
    rr_get_result();

    rr_read_shm_events();

    for (int i=0;i<2; i++) {
        rr_event_log *event = rr_smp_event_log_queues[i];
        while (event != NULL) {
            // printf("Get event %d, 0x%lx, %lu\n", event->id, event->rip, event->inst_cnt);
            event = event->next;
        }
    }

    rr_record_settle_events();

    rr_print_events_stat();

    if (!skip_save){
        rr_save_events();
        rr_dma_post_record();
        rr_network_dma_post_record();

        rr_save_checkpoints();
    }

    rr_reset_ivshmem();
    remove("/dev/shm/record");

    if (exit_record)
        exit(10);
}

void replay_ready(void)
{
    printf("replay initial queue header enabled=%d, current_byte=%lu\n",
           initial_queue_header->rr_enabled, initial_queue_header->current_byte);
    memcpy(ivshmem_base_addr, initial_queue_header, sizeof(rr_event_guest_queue_header));
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

__attribute_maybe_unused__ static unsigned long abs_value(unsigned long a, unsigned long b)
{
    if (a > b)
        return a - b;
    else
        return b - a;
}

__attribute_maybe_unused__ static bool
is_out_record_phase(CPUState *cpu, rr_event_log *event)
{
    if (event->type == EVENT_TYPE_INTERRUPT && event->inst_cnt == 0) {
        if (total_event_number - replayed_event_num < 5) {
            return true;
        }
    }

    return false;
}

__attribute_maybe_unused__ static bool wait_see_next = false;

void rr_replay_interrupt(CPUState *cpu, int *interrupt)
{    
    X86CPU *x86_cpu;
    CPUArchState *env;
    bool mismatched = false;
    bool matched = false;

    try_replay_dma(cpu, 0);

    qemu_mutex_lock(&replay_queue_mutex);

    if (replay_finished()) {
        if (started_replay) {
            finish_replay();            
        }

        *interrupt = -1;
        goto finish;
    } 
    // else {
    //     if (is_out_record_phase(cpu, rr_event_log_head)) {
    //         finish_replay();
    //     }
    // }

    x86_cpu = X86_CPU(cpu);
    env = &x86_cpu->env;

    if (cpu->cpu_index != rr_event_log_head->id) {
        *interrupt = -1;
        goto finish;
    }

    if (rr_event_log_head->type == EVENT_TYPE_INTERRUPT) {

        if (env->eip == rr_event_log_head->rip && env->regs[R_ECX] == rr_event_log_head->event.interrupt.regs.rcx) {
            if (abs_value(cpu->rr_executed_inst, rr_event_log_head->inst_cnt) < 4) {
                qemu_log("temp fixed the cpu number, %lu -> %lu, rcx=0x%lx\n",
                         cpu->rr_executed_inst, rr_event_log_head->inst_cnt, env->regs[R_ECX]);
                cpu->rr_executed_inst = rr_event_log_head->inst_cnt;
                matched = true;
            }
        }

        // if (wait_see_next) {
        //     if (env->eip == cpu->last_pc) {

        //     } else {
        //         if (env->eip == rr_event_log_head->rip) {
        //             matched = true;
        //         } else {
        //             mismatched = true;
        //         }

        //         wait_see_next = false;
        //     }
        // } else if (rr_event_log_head->inst_cnt == cpu->rr_executed_inst) {
            // if (env->eip < 0xBFFFFFFFFFFF) {
            //     env->eip = rr_event_log_head->rip;
            // }

        //     if (env->eip == rr_event_log_head->rip) {
        //         matched = true;
        //     } else {
        //         wait_see_next = true;
        //     }
        // }
        
        if (cpu->force_interrupt) {
            matched = true;
            cpu->force_interrupt = false;
            // cpu->rr_executed_inst--;
        } 
        // else {
        //     if (rr_event_log_head->inst_cnt == cpu->rr_executed_inst + 1 && env->eip == rr_event_log_head->rip) {
        //         matched = true;
        //         cpu->rr_executed_inst++;
        //     }
        // }

        if (matched) {
            // cpu->rr_executed_inst--;
            *interrupt = CPU_INTERRUPT_HARD;
            LOG_MSG("Ready to replay int request, cr0=%lx\n", env->cr[0]);
            // dump_cpus_state();
            // cpu->rr_executed_inst++;

            goto finish;
        }

        if (mismatched) {
            LOG_MSG("Mismatched, interrupt=%d inst number=%lu, actual inst number=%lu, rip=0x%lx, actual rip=0x%lx\n", 
                    rr_event_log_head->event.interrupt.vector, rr_event_log_head->inst_cnt, cpu->rr_executed_inst,
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
            qemu_cond_signal(other_cpu->replay_cond);
            smp_wmb();
        }
    }
    qemu_log("inform other cpus\n");
    qemu_cond_broadcast(&replay_cond);
}


void rr_do_replay_exception(CPUState *cpu, int user_mode)
{
    X86CPU *x86_cpu;
    CPUArchState *env;
    unsigned long dr6_reserved = 0xFFFF0FF0;
    rr_event_log *temp_node;

    x86_cpu = X86_CPU(cpu);
    env = &x86_cpu->env;

    qemu_mutex_lock(&replay_queue_mutex);

    if (rr_event_log_head->type != EVENT_TYPE_EXCEPTION) {
        printf("rr_do_replay_exception: Unexpected exception: addr=0x%lx\n", env->cr[2]);
        cpu->cause_debug = 1;
        goto finish;
    }

    if (rr_event_log_head->event.exception.exception_index == DB_VECTOR) {
        if (rr_event_log_head->event.exception.regs.rip > 0xBFFFFFFFFFFF) {
            // The exception happens during the kernel
            if (rr_event_log_head->next && rr_event_log_head->next->type == EVENT_TYPE_EXCEPTION) {
                if (rr_event_log_head->next->event.exception.exception_index == BP_VECTOR) {
                    temp_node = rr_event_log_head->next;

                    rr_event_log_head->next = temp_node->next;
                    temp_node->next = rr_event_log_head;

                    rr_event_log_head = temp_node;
                }
                printf("Swapped nodes, current=%d\n", rr_event_log_head->event.exception.exception_index);
            }
        }
    }

    cpu->exception_index = rr_event_log_head->event.exception.exception_index;

    // printf("Exception error code %d\n", rr_event_log_head->event.exception.error_code);
    LOG_MSG("Ready to replay exception: %d, inst=%lu\n", cpu->exception_index, cpu->rr_executed_inst);
   

    switch (cpu->exception_index) {
        case PF_VECTOR:
            env->cr[2] = rr_event_log_head->event.exception.cr2;
            env->error_code = rr_event_log_head->event.exception.error_code;
            break;
        case GP_VECTOR:
            env->error_code = rr_event_log_head->event.exception.error_code;
            break;
        case DB_VECTOR:
            env->dr[6] = rr_event_log_head->event.exception.cr2 ^ dr6_reserved;
            env->error_code = rr_event_log_head->event.exception.error_code;
            if (rr_event_log_head->event.exception.inst_cnt > 0) {
                cpu->rr_executed_inst = rr_event_log_head->event.exception.inst_cnt;
            }
            append_to_queue(EVENT_TYPE_EXCEPTION, &(rr_event_log_head->event.exception));
            break;
        case BP_VECTOR:
            break;
        default:
            break;
    }

    rr_event_log_head->user_mode = user_mode;

    if (user_mode) {
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
        env->exception_is_int = 0;
        env->eip = rr_event_log_head->event.exception.regs.rip;
        env->eflags = rr_event_log_head->event.exception.regs.rflags;
    }

    sync_spin_inst_cnt(cpu, rr_event_log_head);

    LOG_MSG("Replayed exception %d, logged: cr2=0x%lx, error_code=%d, current: cr2=0x%lx, dr6=0x%lx, error_code=%d, eflags=0x%lx, rip=0x%lx, event number=%d\n", 
           rr_event_log_head->event.exception.exception_index,
           rr_event_log_head->event.exception.cr2,
           rr_event_log_head->event.exception.error_code, env->cr[2], env->dr[6], env->error_code, env->eflags, env->eip, replayed_event_num);

    if (cpu->exception_index != PF_VECTOR) {
        rr_pop_event_head();
    }

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
    if (!kernel_user_access_pf && !kernel_user_access_pf_cfu && !kernel_user_access_pf_strnlen) {
        return;
    }

    LOG_MSG("Post replay exception\n");

    if (kernel_user_access_pf)
        rr_do_replay_gfu_begin(cpu, 1);
    else if (kernel_user_access_pf_cfu)
        rr_do_replay_cfu(cpu, 1);

    kernel_user_access_pf = false;
    kernel_user_access_pf_cfu = false;
    kernel_user_access_pf_strnlen = false;
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
        cpu->cause_debug = true;
        // return;
    } else {
        printf("Expected PF address: 0x%lx\n", env->cr[2]);
    }

    LOG_MSG("[CPU %d]Replayed exception %d, logged: cr2=0x%lx, error_code=%d, current: cr2=0x%lx, error_code=%d, event number=%d\n", 
            cpu->cpu_index, rr_event_log_head->event.exception.exception_index,
            rr_event_log_head->event.exception.cr2,
            rr_event_log_head->event.exception.error_code, env->cr[2], env->error_code, replayed_event_num);

    // if (get_replayed_event_num() >= 620463)
    //     cpu->cause_debug = 1;
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

    // if (rr_event_log_head->type == EVENT_TYPE_EXCEPTION) {
    //     if (rr_event_log_head->event.exception.cr2 == env->cr[2]) {
    //         printf("Pop out redundant event\n");
    //         rr_pop_event_head();
    //     }
    // }

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
    // env->cr[3] = rr_event_log_head->event.syscall.cr3;

    cpu->rr_executed_inst--;

    LOG_MSG("[%d]Replayed syscall=%lu, cr3=0x%lx, inst_cnt=%lu, replayed event number=%d\n",
            cpu->cpu_index, env->regs[R_EAX], env->cr[3], cpu->rr_executed_inst, replayed_event_num);

    // sync_spin_inst_cnt(cpu, rr_event_log_head);

    syscall_spin_cnt = rr_event_log_head->event.syscall.spin_count;

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

    if (rr_event_log_head->id != cpu->cpu_index) {
        qemu_log("Unmatched cpu id: current=%d, head=%d\n",
                 cpu->cpu_index, rr_event_log_head->id);
        cpu->cause_debug = 1;
        goto finish;
    }

    if (rr_event_log_head->type != EVENT_TYPE_IO_IN) {
        LOG_MSG("Expected %d event, found %d, rip=0x%lx, cpu_id=%d\n",
                 EVENT_TYPE_IO_IN, rr_event_log_head->type, env->eip, cpu->cpu_index);
        cpu->cause_debug = 1;
        goto finish;
    }

    if (rr_event_log_head->inst_cnt != cpu->rr_executed_inst) {
        if (env->eip == cpu->last_replayed_addr && \
            (cpu->rr_executed_inst == cpu->last_replayed_inst || cpu->rr_executed_inst - 1 == cpu->last_replayed_inst)){
            /*
            Here for repetitive instructions.
            */
        } else {
            if (abs_value(cpu->rr_executed_inst, rr_event_log_head->inst_cnt) <= 2) {
                cpu->rr_executed_inst = rr_event_log_head->inst_cnt;
            } else {
                LOG_MSG("Mismatched IO Input, expected inst cnt %lu, found %lu, rip=0x%lx, actual_rip=0x%lx\n",
                        rr_event_log_head->inst_cnt, cpu->rr_executed_inst, rr_event_log_head->rip, env->eip);
                //  cpu->rr_executed_inst = rr_event_log_head->inst_cnt;
                //  abort();
                cpu->rr_executed_inst = rr_event_log_head->inst_cnt;
                cpu->cause_debug = 1;
            }
        }
    }

    if (rr_event_log_head->rip != env->eip) {
        LOG_MSG("Unexpected IO Input RIP, expected 0x%lx, actual 0x%lx\n",
            rr_event_log_head->rip, env->eip);
        // abort();
        cpu->cause_debug = 1;
        goto finish;
    }

    *input = rr_event_log_head->event.io_input.value;

    // if (*input == 0x10000010410040) {
    //     cpu->cause_debug = 1;
    // }

    LOG_MSG("[CPU %d]Replayed io input=0x%lx, inst_cnt=%lu, cpu_id=%d, rip=0x%lx, replayed event number=%d\n",
             cpu->cpu_index, *input, cpu->rr_executed_inst,
             rr_event_log_head->id, rr_event_log_head->rip, replayed_event_num);

    append_to_queue(EVENT_TYPE_IO_IN, &(rr_event_log_head->event.io_input));
    rr_pop_event_head();

finish:
    cpu->last_replayed_addr = env->eip;
    cpu->last_replayed_inst = cpu->rr_executed_inst;

    qemu_mutex_unlock(&replay_queue_mutex);
    return;
}

void rr_do_replay_mmio(unsigned long *input)
{
    CPUState *cpu;
    CPUArchState *env;
    X86CPU *x86_cpu;
    unsigned long inst_cnt = 0;

    qemu_mutex_lock(&replay_queue_mutex);

    if (rr_event_log_head->type != EVENT_TYPE_MMIO) {
        LOG_MSG("Expected %d event, found %d\n", EVENT_TYPE_MMIO, rr_event_log_head->type);
        
        CPU_FOREACH(cpu) {
            cpu->cause_debug = 1;
            x86_cpu = X86_CPU(cpu);
            env = &x86_cpu->env;
            printf("fault addr 0x%lx, inst cnt %lu\n", env->eip, cpu->rr_executed_inst);
        }
        // cpu->cause_debug = 1;
        // abort();
        goto finish;
        // return;
    }

    // if (rr_event_log_head->inst_cnt != cpu->rr_executed_inst) {
    //     qemu_log("Mismatched MMIO Input, expected inst cnt %lu, found %lu, rip=0x%lx\n",
    //            rr_event_log_head->inst_cnt, cpu->rr_executed_inst, rr_event_log_head->rip);
    //      cpu->rr_executed_inst = rr_event_log_head->inst_cnt;
    // }

    *input = rr_event_log_head->event.io_input.value;

    CPU_FOREACH(cpu) {
        x86_cpu = X86_CPU(cpu);
        env = &x86_cpu->env;
        inst_cnt = cpu->rr_executed_inst;
    }

    qemu_log("Replayed mmio input=0x%lx, inst_cnt=%lu, expected_inst_cnt=%lu, replayed event number=%d\n",
             *input, inst_cnt, rr_event_log_head->event.io_input.inst_cnt, replayed_event_num);
    printf("Replayed mmio input=0x%lx, inst_cnt=%lu, replayed event number=%d\n",
            *input, inst_cnt, replayed_event_num);

    append_to_queue(EVENT_TYPE_MMIO, &(rr_event_log_head->event.io_input));
    rr_pop_event_head();

finish:
    qemu_mutex_unlock(&replay_queue_mutex);
    return;
}

void rr_do_replay_rdpmc(CPUState *cpu, unsigned long long *val)
{
    X86CPU *x86_cpu;
    CPUArchState *env;

    x86_cpu = X86_CPU(cpu);
    env = &x86_cpu->env;

    qemu_mutex_lock(&replay_queue_mutex);

    if (rr_event_log_head->id != cpu->cpu_index) {
        qemu_log("Unmatched cpu id: current=%d, head=%d\n",
                 cpu->cpu_index, rr_event_log_head->id);
        cpu->cause_debug = 1;
        goto finish;
    }

    if (rr_event_log_head->type != EVENT_TYPE_IO_IN) {
        LOG_MSG("Expected %d event, found %d, rip=0x%lx, cpu_id=%d\n",
                 EVENT_TYPE_IO_IN, rr_event_log_head->type, env->eip, cpu->cpu_index);
        cpu->cause_debug = 1;
        goto finish;
    }

    // if (rr_event_log_head->inst_cnt != cpu->rr_executed_inst) {
    //     qemu_log("Mismatched RDPMC, expected inst cnt %lu, found %lu, rip=0x%lx, actual_rip=0x%lx\n",
    //              rr_event_log_head->inst_cnt, cpu->rr_executed_inst, rr_event_log_head->rip, env->eip);
    //     cpu->cause_debug = 1;
    // }

    if (rr_event_log_head->rip != env->eip) {
        printf("Unexpected RDPMC RIP, expected 0x%lx, actual 0x%lx\n",
            rr_event_log_head->rip, env->eip);
        abort();
    }

    *val = rr_event_log_head->event.io_input.value;

    LOG_MSG("[CPU %d]Replayed RDPMC=0x%llx, inst_cnt=%lu, cpu_id=%d, rip=0x%lx, replayed event number=%d\n",
             cpu->cpu_index, *val, cpu->rr_executed_inst,
             rr_event_log_head->id, rr_event_log_head->rip, replayed_event_num);


    append_to_queue(EVENT_TYPE_IO_IN, &(rr_event_log_head->event.io_input));

finish:
    rr_pop_event_head();

    qemu_mutex_unlock(&replay_queue_mutex);
}

void rr_do_replay_rdtsc(CPUState *cpu, unsigned long *tsc)
{
    qemu_mutex_lock(&replay_queue_mutex);

    if (rr_event_log_head->type != EVENT_TYPE_RDTSC) {
        LOG_MSG("Expected %d event, found %d, inst_cnt=%lu\n",
                 EVENT_TYPE_RDTSC, rr_event_log_head->type, cpu->rr_executed_inst);
        // abort();
        cpu->cause_debug = true;
        // rr_pop_event_head();
        goto finish;
    }

    *tsc = rr_event_log_head->event.io_input.value;

    LOG_MSG("[CPU %d]Replayed rdtsc=%lx, inst=%lu, replayed event number=%d\n",
            cpu->cpu_index, *tsc, rr_event_log_head->event.io_input.inst_cnt, replayed_event_num);

finish:
    rr_pop_event_head();

    qemu_mutex_unlock(&replay_queue_mutex);
    return;
}

void rr_do_replay_release(CPUState *cpu)
{
    CPUState *cs;

    qemu_mutex_lock(&replay_queue_mutex);

    // if (rr_event_log_head->type != EVENT_TYPE_RELEASE) {
    //     printf("Unexpected %d, expected lock release, inst_cnt=%lu\n",
    //            rr_event_log_head->type, cpu->rr_executed_inst);
    //     cpu->cause_debug = true;
    //     goto finish;
    //     // abort();
    // } else {
    //     rr_pop_event_head();
    // }

    if (rr_event_log_head && rr_event_log_head->id == cpu->cpu_index) {
        goto finish;
    }

    qemu_log("[CPU %d]Replayed release, replayed event number=%d\n",
             cpu->cpu_index, replayed_event_num);
    printf("[CPU %d]Replayed release, replayed event number=%d\n",
            cpu->cpu_index, replayed_event_num);

    if (rr_event_log_head != NULL) {
        current_owner = rr_event_log_head->id;
        qemu_log("Next owner %d\n", current_owner);
    }

    // dump_cpus_state();

    CPU_FOREACH(cs) {
        if (cs->cpu_index == current_owner) {
            qemu_log("inform cpu %d\n", current_owner);
            qemu_cond_signal(cs->replay_cond);
        }
    }
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

    qemu_log("Replaying rdseed %lu\n", rr_event_log_head->event.gfu.val);

    *val = rr_event_log_head->event.gfu.val;

    qemu_log("Replayed rdseed=%lu, replayed event number=%d\n", *val, replayed_event_num);
    printf("Replayed rdseed=%lu, replayed event number=%d\n", *val, replayed_event_num);

    rr_pop_event_head();

    qemu_mutex_unlock(&replay_queue_mutex);
}

void rr_do_replay_intno(CPUState *cpu, int *intno)
{
    X86CPU *x86_cpu;
    CPUArchState *env;
    __attribute_maybe_unused__ rr_event_log *node = rr_event_log_head;

    if (rr_event_log_head == NULL) {
        qemu_log("No events anymore\n");
        abort();
    }

    if (rr_event_log_head->type == EVENT_TYPE_INTERRUPT) {
        x86_cpu = X86_CPU(cpu);
        env = &x86_cpu->env;
    
        *intno = rr_event_log_head->event.interrupt.vector;

        env->regs[R_EAX] = rr_event_log_head->event.interrupt.regs.rax;
        env->regs[R_EBX] = rr_event_log_head->event.interrupt.regs.rbx;
        env->regs[R_ECX] = rr_event_log_head->event.interrupt.regs.rcx;
        env->regs[R_EDX] = rr_event_log_head->event.interrupt.regs.rdx;
        env->regs[R_EBP] = rr_event_log_head->event.interrupt.regs.rbp;
        env->regs[R_ESP] = rr_event_log_head->event.interrupt.regs.rsp;
        env->regs[R_EDI] = rr_event_log_head->event.interrupt.regs.rdi;
        env->regs[R_ESI] = rr_event_log_head->event.interrupt.regs.rsi;
        env->regs[R_R8] = rr_event_log_head->event.interrupt.regs.r8;
        env->regs[R_R9] = rr_event_log_head->event.interrupt.regs.r9;
        env->regs[R_R10] = rr_event_log_head->event.interrupt.regs.r10;
        env->regs[R_R11] = rr_event_log_head->event.interrupt.regs.r11;
        env->regs[R_R12] = rr_event_log_head->event.interrupt.regs.r12;
        env->regs[R_R13] = rr_event_log_head->event.interrupt.regs.r13;
        env->regs[R_R14] = rr_event_log_head->event.interrupt.regs.r14;
        env->regs[R_R15] = rr_event_log_head->event.interrupt.regs.r15;
        // env->eflags = rr_event_log_head->event.interrupt.regs.rflags;

        // Interrupt address is in user mode, we should replay the rip
        // because of the rseq handling on next return to user mode.
        if (rr_event_log_head->rip < 0xBFFFFFFFFFFF) {
            env->eip = rr_event_log_head->rip;
        }

        sync_spin_inst_cnt(cpu, rr_event_log_head);

        if (rr_event_log_head->event.interrupt.from == 0) {
            append_to_queue(EVENT_TYPE_INTERRUPT, &(rr_event_log_head->event.interrupt));
        }

        /*
        qemu_log("[CPU %d]Replayed interrupt vector=%d, RIP on replay=0x%lx,"\
                 "inst_cnt=%lu, cpu_id=%d, cr0=%lx, replay eflags=0x%lx, record eflags=0x%llx, replayed event number=%d\n",
                 cpu->cpu_index, *intno, env->eip, cpu->rr_executed_inst,
                 rr_event_log_head->id, env->cr[0], env->eflags, node->event.interrupt.regs.rflags, replayed_event_num); */
        LOG_MSG("[CPU %d]Replayed interrupt vector=%d, RIP on replay=0x%lx,"\
                 "inst_cnt=%lu, cpu_id=%d, cr0=%lx, replay eflags=0x%lx, record eflags=0x%llx replayed event number=%d\n",
                 cpu->cpu_index, *intno, env->eip, cpu->rr_executed_inst,
                 rr_event_log_head->id, env->cr[0],  env->eflags, node->event.interrupt.regs.rflags, replayed_event_num);

        rr_pop_event_head();

        if (!started_replay) {
            started_replay = 1;
        }

        return;
    }

}

void rr_do_replay_page_map(CPUState *cpu)
{
    X86CPU *x86_cpu;
    CPUArchState *env;
    int ret;
    rr_event_log *node = rr_event_log_head;

    x86_cpu = X86_CPU(cpu);
    env = &x86_cpu->env;

    if (node->type != EVENT_TYPE_CFU) {
        cpu->cause_debug = true;
        printf("Expected CFU, current %d\n", node->type);
        return;
    }

    if (node->event.cfu.src_addr != env->regs[R_ESI]) {
        cpu->cause_debug = true;
        printf("src_addr(0x%lx) != expected(0x%lx)", node->event.cfu.src_addr, env->regs[R_ESI]);
        return;
    }

    ret = cpu_memory_rw_debug(cpu, node->event.cfu.src_addr,
                              node->event.cfu.data,
                              node->event.cfu.len, true);
    if (ret < 0) {
        printf("Failed too write to %lx\n", node->event.cfu.src_addr);
    }

    rr_pop_event_head();
}


uint64_t rr_num_instr_before_next_interrupt(void)
{
    if (rr_event_log_head == NULL) {
        if (!initialized_replay) {
            rr_load_events();
            rr_dma_network_pre_replay();
            initialize_replay();

            initialized_replay = 1;

            if (!rr_event_log_head)
                return 0;

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

unsigned long rr_one_cpu_rip(void)
{
    CPUState *cpu;
    CPUArchState *env;
    X86CPU *x86_cpu;

    CPU_FOREACH(cpu) {
        kvm_arch_get_registers(cpu);
        x86_cpu = X86_CPU(cpu);
        env = &x86_cpu->env;
        return env->eip;
    }

    return 0;
}

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

static int record_event(void *event_addr)
{
    rr_event_entry_header *event_header;
    int copied;
    rr_event_log *event_record;

    event_header = (rr_event_entry_header *)(event_addr);

    event_record = rr_event_log_new_from_event_shm(event_addr + sizeof(rr_event_entry_header),
                                                   event_header->type, &copied);
    // qemu_log("event type %d\n", event_record->type);
    if (rr_event_cur == NULL) {
        rr_event_log_head = event_record;
        rr_event_cur = event_record;
    } else {
        rr_event_cur->next = event_record;
        rr_event_cur = rr_event_cur->next;
    }

    rr_event_cur->next = NULL;

    return copied + sizeof(rr_event_entry_header);
}

static void rr_read_shm_events_info(void)
{
    rr_event_guest_queue_header *header = (rr_event_guest_queue_header *)ivshmem_base_addr;
    unsigned long total_bytes = header->rotated_bytes + header->current_byte;

    printf("current pos %u, rotated_bytes %lu, current_bytes %lu, total_bytes %lu\n",
           header->current_pos, header->rotated_bytes, header->current_byte, total_bytes);
}

__attribute_maybe_unused__
static void rr_read_shm_events(void)
{
    rr_event_guest_queue_header *header = (rr_event_guest_queue_header *)ivshmem_base_addr;
    void *addr = ivshmem_base_addr + header->header_size;
    unsigned long bytes = 0;
    unsigned long total_bytes = header->header_size;
    unsigned int cur_pos = header->current_pos;
    // unsigned long cur_byte = header->current_byte;
    int pos = 0;

    while(pos < cur_pos) {
        // qemu_log("event addr=%p pos=%d %u\n", addr, pos, cur_pos);
        bytes = record_event(addr);
        total_bytes += bytes;
        addr += bytes;
        pos++;
    }

    if (total_bytes != header->current_byte)
        printf("Read byte %lu != recorded byte %lu\n", total_bytes, header->current_byte);
}

void rr_register_ivshmem(RAMBlock *rb)
{
    ivshmem_base_addr = rb->host;

    rr_event_guest_queue_header *header = (rr_event_guest_queue_header *)ivshmem_base_addr;
    printf("Host addr for shared memory: %p\nHeader info:\ntotal_pos=%u\nrr_endabled=%u, entry_size=%lu\n",
           ivshmem_base_addr, header->total_pos, header->rr_enabled, sizeof(rr_event_log));

    init_lock_owner();
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

int rr_inc_inst(CPUState *cpu, unsigned long next_pc, TranslationBlock *tb)
{
    X86CPU *c = X86_CPU(cpu);
    CPUX86State *env = &c->env;

    if (tb->io_inst & IO_INST_REP) {
        qemu_log("IO_INST_REP\n");
    }

    if (next_pc != cpu->last_pc) {
        cpu->rr_executed_inst++;
    } else if (tb->io_inst & IO_INST_REP_OUT) {
        if (env->regs[R_ECX] == 1)
            cpu->rr_executed_inst++;
        cpu->rr_executed_inst++;
    } else if ((tb->io_inst & IO_INST_REP_IN) && env->regs[R_ECX] == 1) {
        qemu_log("rep in, inc\n");
        // if (env->regs[R_ECX] == 1)
        //     cpu->rr_executed_inst++;
        cpu->rr_executed_inst++;
    }

    // if (tb->io_inst & STO_INST_REP) {
    //     qemu_log("Rep IO Instruction\n");
    //     qemu_log("[cpu %d]0x%lx, inst_cnt=%lu\n", cpu->cpu_index, tb->pc, cpu->rr_executed_inst);
    //     log_regs(cpu);
    //     log_tb(cpu, tb);
    // }

    return 0;
}


void rr_handle_kernel_entry(CPUState *cpu, unsigned long bp_addr, unsigned long inst_cnt) {
    X86CPU *c = X86_CPU(cpu);
    CPUX86State *env = &c->env;

    if (kvm_enabled())
        kvm_arch_get_registers(cpu);

    // printf("Step: 0x%lx Inst: %lu, ECX=%lu\n", env->eip, inst_cnt, env->regs[R_ECX]);

    target_ulong rsi_value = env->regs[R_EDI] + 512;
    uint64_t buffer = 0;
    cpu_memory_rw_debug(cpu, rsi_value, &buffer, sizeof(buffer), 0);

    qemu_log("Step: 0x%lx Inst: %lu, rax=0x%lx, rdx=0x%lx, xcr0=0x%lx, buffer=0x%lx\n",
             env->eip, inst_cnt, env->regs[R_EAX], env->regs[R_EDX], env->xcr0, buffer);

    // qemu_log("Step: 0x%lx Inst: %lu eflags=0x%lx, rax=0x%lx, rbx=0x%lx, rcx=0x%lx,"
    //          "rdx=0x%lx, rsi=0x%lx, rdi=0x%lx, rsp=0x%lx, rbp=0x%lx, buffer=0x%lx\n",
    //          env->eip, inst_cnt, env->eflags, env->regs[R_EAX], env->regs[R_EBX],
    //          env->regs[R_ECX], env->regs[R_EDX], env->regs[R_ESI], env->regs[R_EDI],
    //          env->regs[R_ESP], env->regs[R_EBP], buffer);

    return;

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
        case E1000_CLEAN:
            qemu_log("[CPU-%d]check_trace e1000_clean: %lu\n", cpu->cpu_index, inst_cnt);
            break;
        case E1000_CLEAN_MID:
            qemu_log("[CPU-%d]check_trace e1000_clean_mid: %lu\n", cpu->cpu_index, inst_cnt);
            break;
        case COSTUMED1:
            qemu_log("[CPU-%d]check_trace costumed1: %lu, rax=0x%lx, rdx=0x%lx, eflags=0x%lx\n", cpu->cpu_index, inst_cnt, env->regs[R_EAX], env->regs[R_EDX], env->eflags);
            break;
        case COSTUMED2:
            qemu_log("[CPU-%d]check_trace costumed2: %lu, rbx=0x%lx\n", cpu->cpu_index, inst_cnt, env->regs[R_EBX]);
            break;
        case COSTUMED3:
            qemu_log("[CPU-%d]check_trace costumed3: %lu, r12=0x%lx, rbx=0x%lx, eflags=0x%lx\n", cpu->cpu_index, inst_cnt, env->regs[R_R12], env->regs[R_EBX], env->eflags);

            // target_ulong rsp_value = env->regs[R_ESP];
            // target_ulong return_address;
            // cpu_memory_rw_debug(cpu, rsp_value, &return_address, sizeof(return_address), 0);
            // qemu_log("[CPU-%d]check_trace costumed3: %lu, addr=0x%lx\n", cpu->cpu_index, inst_cnt, return_address);
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


void append_to_queue(int type, void *opaque)
{
    rr_event_guest_queue_header *header = (rr_event_guest_queue_header *)ivshmem_base_addr;
    rr_event_entry_header entry_header = {
        .type = type,
    };
    int event_size = 0;
    
    switch (type)
    {
    case EVENT_TYPE_MMIO:
        event_size = sizeof(rr_io_input);
        break;
    case EVENT_TYPE_INTERRUPT:
        event_size = sizeof(rr_interrupt);
        break;
    case EVENT_TYPE_IO_IN:
    case EVENT_TYPE_RDTSC:
        event_size = sizeof(rr_io_input);
        break;
    case EVENT_TYPE_DMA_DONE:
        event_size = sizeof(rr_dma_done);
        break;
    case EVENT_TYPE_EXCEPTION:
        event_size = sizeof(rr_exception);
        break;
    default:
        printf("Unexpected event type %d\n", type);
        abort();
        break;
    }

    if (header->current_byte + event_size + sizeof(rr_event_entry_header) >= header->total_size) {
        header->rotated_bytes += (header->current_byte - header->header_size);
        header->current_byte = header->header_size;
        header->current_pos = 0;
    }

    memcpy(ivshmem_base_addr + header->current_byte, &entry_header, sizeof(rr_event_entry_header));
    header->current_byte += sizeof(rr_event_entry_header);

    memcpy(ivshmem_base_addr + header->current_byte, opaque, event_size);
    header->current_byte += event_size;

    header->current_pos++;
}

unsigned long get_recorded_num(void)
{
    rr_event_guest_queue_header *header = (rr_event_guest_queue_header *)ivshmem_base_addr;
    return header->current_pos;
}

int get_lock_owner(void) {
    int cpu_id;

    memcpy(&cpu_id, ivshmem_base_addr + sizeof(rr_event_guest_queue_header), sizeof(int));

    return cpu_id;
}

int replay_get_current_owner(void)
{
    return current_owner;
}

static void init_lock_owner(void)
{
    int cpu_id = 0;

    memcpy(ivshmem_base_addr + sizeof(rr_event_guest_queue_header), &cpu_id, sizeof(int));
}

void set_count_syscall(int val)
{
    count_syscall = val;
}

void set_snapshot_period(int val)
{
    snapshot_period = val;
}


void rr_rotate_shm_queue(void)
{
    rr_event_guest_queue_header *header = (rr_event_guest_queue_header *)ivshmem_base_addr;
    header->rotated_bytes += (header->current_byte - header->header_size);
    header->current_byte = header->header_size;
    total_pos += header->current_pos;
    header->current_pos = 0;
}

static void rr_cleanup_local_queue(void)
{
    rr_event_log *cur = rr_event_log_head;
    rr_event_log *next;

    while (cur != NULL) {
        next = cur->next;
        free(cur);
        cur = next;
    } 

    rr_event_log_head = NULL;
    rr_event_cur = NULL;
}

void rr_handle_queue_full(void)
{
    rr_read_shm_events();
    rr_save_events();

    rr_rotate_shm_queue();

    qemu_log("Rotated log queue\n");
    rr_print_events_stat();
    
    rr_log_all_events(rr_event_log_head);

    rr_cleanup_local_queue();
}

unsigned long get_total_executed_inst(void)
{
    CPUState *cs;
    unsigned long total_executed_inst = 0;

    CPU_FOREACH(cs) {
        total_executed_inst += cs->rr_executed_inst;
    }

    return total_executed_inst;
}

void replay_snapshot_checkpoint(void)
{
    unsigned long total_executed_inst;

    if (!replay_info->fptr) {
        return;
    }

    total_executed_inst = get_total_executed_inst();
    if (total_executed_inst != replay_info->next_checkpoint_inst) {
        return;
    }

    qemu_mutex_lock_iothread();
    replay_save_snapshot(replay_info);
    qemu_mutex_unlock_iothread();

    replay_info->next_checkpoint_inst += snapshot_period;
}

static void replay_save_snapshot(rr_replay_info *cur_replay_info)
{
    char fname[20];
    CPUState *cpu;
    rr_replay_info_node *replay_info_node;

    sprintf(fname, "replay-snapshot.%d", cur_replay_info->cur_node_id);

    rr_save_snapshot(fname, NULL);

    replay_info_node = (rr_replay_info_node *)malloc(sizeof(rr_replay_info_node));
    CPU_FOREACH(cpu) {
        replay_info_node->cpu_inst_list[cpu->cpu_index] = cpu->rr_executed_inst;
    }

    replay_info_node->cur_event_num = replayed_event_num;
    replay_info_node->cur_event_type = rr_event_log_head->type;
    replay_info_node->lock_owner = current_owner;
    replay_info_node->total_inst_cnt = get_total_executed_inst();

    LOG_MSG("Replay snapshot number %d is taken\n", cur_replay_info->cur_node_id);
    cur_replay_info->cur_node_id++;

    replay_save_progress_info(replay_info_node);
}

static void replay_save_progress_info(rr_replay_info_node *info_node)
{
    fwrite(info_node, sizeof(rr_replay_info_node), 1, replay_info->fptr);
}

int replay_find_nearest_snapshot(unsigned long inst_cnt)
{
    rr_replay_info_node *node = replay_info->replay_info_head;
    int id = 0;
    unsigned long total_inst = get_total_executed_inst();

    while (node != NULL && node->next != NULL)
    {
        if (node->total_inst_cnt < total_inst && \
            node->next->total_inst_cnt >= total_inst) {
            break;
        }
        node = node->next;
        id++;
    }
    printf("nearest inst=%lu, event_type=%d\n", node->total_inst_cnt, node->cur_event_type);

    return id;
}
