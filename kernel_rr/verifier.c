#include "qemu/osdep.h"
#include "qemu-common.h"
#include "exec/log.h"
#include "migration/snapshot.h"

#include "target/i386/cpu.h"
#include "cpu.h"
#include "sysemu/kernel-rr.h"
#include "accel/kvm/kvm-cpus.h"

#include "sysemu/kvm.h"

typedef struct rr_checkpoint_t {
    unsigned long inst_cnt;
    unsigned long rip;
    unsigned long regs[16];
    unsigned long crs[5];
    SegmentCache segs[6];
    unsigned long eflags;
    struct rr_checkpoint_t *next;
} rr_checkpoint;


rr_checkpoint *check_points[32];
static int verify_replay = 0;
static int passed = 0;


int is_verify_replay(void)
{
    return verify_replay;
}

void rr_init_checkpoints(void)
{
    for (int i=0; i < 32; i++) {
        check_points[i] = NULL;
    }
}

static void save_cpu_checkpoints(CPUState *cpu)
{
    char fname[20];
    FILE *fptr;
    rr_checkpoint *head = check_points[cpu->cpu_index];
    int c_num = 0;

    if (!head)
        return;

    sprintf(fname, "checkpoint-%d", cpu->cpu_index);
    remove(fname);
    fptr = fopen(fname, "a");

    while (head) {
        fwrite(head, sizeof(rr_checkpoint), 1, fptr);
        head = head->next;
        c_num++;
    }

    fclose(fptr);

    printf("Saved %d checkpoints\n", c_num);
}

static void load_cpu_checkpoints(CPUState *cpu)
{
    char fname[20];
    FILE *fptr;
    rr_checkpoint node;
    rr_checkpoint *new_node, *tail_node = NULL;
    int c_num = 0;

    sprintf(fname, "checkpoint-%d", cpu->cpu_index);
    fptr = fopen(fname, "r");

    if (!fptr)
        return;

    while(fread(&node, sizeof(rr_checkpoint), 1, fptr)) {
        new_node = (rr_checkpoint *)malloc(sizeof(rr_checkpoint));

        memcpy(new_node, &node, sizeof(rr_checkpoint));

        if (!check_points[cpu->cpu_index]) {
            check_points[cpu->cpu_index] = new_node;
        }

         qemu_log("[CPU-%d]checkpoint inst %lu, rip=0x%lx\n",
                  cpu->cpu_index, new_node->inst_cnt, new_node->rip);

        if (tail_node == NULL) {
            tail_node = new_node;
        } else {
            tail_node->next = new_node;
            tail_node = tail_node->next;
        }
        c_num++;
    }

    if (c_num > 0)
        verify_replay = 1;

    printf("Loaded %d checkpoints for CPU %d", c_num, cpu->cpu_index);
}

void rr_save_checkpoints(void)
{
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        save_cpu_checkpoints(cpu);
    }
}


void rr_load_checkpoints(void)
{
    CPUState *cpu;

    rr_init_checkpoints();

    CPU_FOREACH(cpu) {
        load_cpu_checkpoints(cpu);
    }
}


static void insert_check_node(CPUState *cpu, unsigned long inst_cnt)
{
    X86CPU *c = X86_CPU(cpu);
    CPUX86State *env = &c->env;
    rr_checkpoint *temp_cp;
    
    rr_checkpoint *cp = (rr_checkpoint *)malloc(sizeof(rr_checkpoint));

    if (env->eip < 0xBFFFFFFFFFFF) {
        return;
    }

    cp->inst_cnt = inst_cnt;
    cp->rip = env->eip;
    for (int i=0; i < CPU_NB_REGS; i++) {
        cp->regs[i] = env->regs[i];
    }

    for (int i=0; i < 5; i++) {
        cp->crs[i] = env->cr[i];
    }

    for (int i=0; i < 6; i++) {
        memcpy(&cp->segs[i], &env->segs[i], sizeof(SegmentCache));
    }

    cp->eflags = env->eflags;
    cp->next = NULL;

    if (check_points[cpu->cpu_index] == NULL) {
        check_points[cpu->cpu_index] = cp;
    } else {
        temp_cp = check_points[cpu->cpu_index];
        while (temp_cp->next != NULL) {
            temp_cp = temp_cp->next;
        }

        if (temp_cp->inst_cnt == inst_cnt) {
            qemu_log("Ignore repetitive point inst cnt=%lu, rip=0x%lx", inst_cnt, cp->rip);
            free(cp);
            return;
        }

        temp_cp->next = cp;
    }

    qemu_log("[CPU-%d]checkpoint inst=%lu, rip=0x%lx\n", cpu->cpu_index, inst_cnt, env->eip);
}


void handle_rr_checkpoint(CPUState *cpu)
{
    unsigned long inst_cnt;
    unsigned long rip;
    int r;

    rip = cpu->kvm_run->debug.arch.pc;
    if (rip == SYSCALL_ENTRY || rip == PF_ENTRY || rip == COSTUMED1 || rip == RR_IRET) {
        r = kvm_reset_counter(cpu);
        if (r != 0) {
            printf("Failed to reset counter %d\n", r);
        }
    }

    if (kvm_enabled()){
        kvm_arch_get_registers(cpu);
        inst_cnt = rr_get_inst_cnt(cpu);
    } else {
        inst_cnt = cpu->rr_executed_inst;
    }

    insert_check_node(cpu, inst_cnt);
}

static unsigned long mask_bit(unsigned long eflags, unsigned long mask) {
    return eflags & ~mask;
}

void handle_replay_rr_checkpoint(CPUState *cpu, int is_rep)
{
    rr_checkpoint *node;
    bool is_bugged = false;

    node = check_points[cpu->cpu_index];
    if (!node) {
        return;
    }

    if (cpu->rr_executed_inst < node->inst_cnt) {
        return;
    }

    if (cpu->rr_executed_inst > node->inst_cnt) {
        LOG_MSG("Check: missed checkpoint: inst=%lu, rip=0x%lx\n", node->inst_cnt, node->rip);
        goto finish;
    }

    X86CPU *c = X86_CPU(cpu);
    CPUX86State *env = &c->env;

    if (is_rep && env->regs[R_ECX] != node->regs[R_ECX]) {
        return;
    }

    if (env->eip != node->rip) {
        is_bugged = true;
        LOG_MSG("BUG: inconsistent RIP current=0x%lx, expected=0x%lx, inst=%lu\n",
                env->eip, node->rip, node->inst_cnt);
        cpu->cause_debug = 1;
        goto finish;
    }

    for (int i=0; i < 5; i++) {
        if (i == 1)
            continue;

        if (node->rip == SYSCALL_ENTRY || node->rip == SYSCALL_ENTRY + 3)
            continue;

        if (env->cr[i] != node->crs[i]) {
            is_bugged = true;
            LOG_MSG("BUG: inconsistent CR%d, rip=0x%lx, current=0x%lx, expected=0x%lx\n",
                     i, env->eip, env->cr[i], node->crs[i]);
            cpu->cause_debug = 1;
            // exit(1);
            goto finish;
        }
    }

    for (int i=0; i < CPU_NB_REGS; i++) {
        if (env->regs[i] != node->regs[i]) {
            is_bugged = true;
            LOG_MSG("BUG: inconsistent #%d reg, rip=0x%lx, current=0x%lx, expected=0x%lx\n",
                     i, env->eip, env->regs[i], node->regs[i]);
            cpu->cause_debug = 1;
            // exit(1);
            goto finish;
        }
    }

    for (int i=0; i < 6; i++) {
        if (env->segs[i].base != node->segs[i].base) {
            is_bugged = true;
            LOG_MSG("BUG: inconsistent SEG%d, rip=0x%lx, current=0x%lx, expected=0x%lx\n",
                     i, env->eip, env->segs[i].base, node->segs[i].base);
            exit(1);
        }
        if (env->segs[i].selector != node->segs[i].selector) {
            is_bugged = true;
            LOG_MSG("BUG: inconsistent SEG%d, rip=0x%lx, current=%u, expected=%u\n",
                     i, env->eip, env->segs[i].selector, node->segs[i].selector);
            exit(1);
        }
    }

    if (!is_bugged) {
        LOG_MSG("Registers are consistent\n");
    }

    if (mask_bit(env->eflags, CC_O | RF_MASK) != mask_bit(node->eflags, CC_O | RF_MASK)) {
        LOG_MSG("BUG: inconsistent eflags current=0x%lx, expected=0x%lx\n", env->eflags, node->eflags);
        // cpu->cause_debug = 1;
        is_bugged = true;
    }

finish:
    if (is_bugged) {
        LOG_MSG("BUGPoint: 0x%lx\n", env->eip);
    } else {
        LOG_MSG("[CPU-%d]checkpoint passed inst=%lu, rip=0x%lx\n",
                cpu->cpu_index, node->inst_cnt, node->rip);
        passed++;
    }

    check_points[cpu->cpu_index] = node->next;
}
