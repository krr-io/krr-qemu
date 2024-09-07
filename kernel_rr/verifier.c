#include "qemu/osdep.h"
#include "qemu-common.h"
#include "exec/log.h"
#include "migration/snapshot.h"

#include "target/i386/cpu.h"
#include "cpu.h"
#include "sysemu/kernel-rr.h"
#include "accel/kvm/kvm-cpus.h"

#include "sysemu/kvm.h"

rr_checkpoint *check_points[32];


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

        if (tail_node == NULL) {
            tail_node = new_node;
        } else {
            tail_node->next = new_node;
            tail_node = tail_node->next;
        }
        c_num++;
    }

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

    cp->inst_cnt = inst_cnt;
    cp->rip = env->eip;
    for (int i=0; i < CPU_NB_REGS; i++) {
        cp->regs[i] = env->regs[i];
    }
    cp->next = NULL;

    if (check_points[cpu->cpu_index] == NULL) {
        check_points[cpu->cpu_index] = cp;
    } else {
        temp_cp = check_points[cpu->cpu_index];
        while (temp_cp->next != NULL) {
            temp_cp = temp_cp->next;
        }

        temp_cp->next = cp;
    }

    qemu_log("[CPU-%d]checkpoint inst=%lu, rip=0x%lx\n", cpu->cpu_index, inst_cnt, env->eip);
}


void handle_rr_checkpoint(CPUState *cpu)
{
    unsigned long inst_cnt;

    if (kvm_enabled()){
        kvm_arch_get_registers(cpu);
        inst_cnt = rr_get_inst_cnt(cpu);
    } else {
        inst_cnt = cpu->rr_executed_inst;
    }

    insert_check_node(cpu, inst_cnt);
}

void handle_replay_rr_checkpoint(CPUState *cpu)
{
    rr_checkpoint *node;

    node = check_points[cpu->cpu_index];
    if (!node) {
        return;
    }

    if (cpu->rr_executed_inst != node->inst_cnt) {
        return;
    }

    X86CPU *c = X86_CPU(cpu);
    CPUX86State *env = &c->env;

    if (env->eip != node->rip) {
        qemu_log("BUG: inconsistent RIP current=0x%lx, expected=0x%lx\n", env->eip, node->rip);
        goto finish;
    }

    for (int i=0; i < CPU_NB_REGS; i++) {
        if (env->regs[i] != node->regs[i]) {
            qemu_log("BUG: inconsistent #%d reg, rip=0x%lx, current=0x%lx, expected=0x%lx\n",
                     i, env->eip, env->regs[i], node->regs[i]);
        }
    }

    qemu_log("[CPU-%d]checkpoint passed inst=%lu, rip=0x%lx\n",
             cpu->cpu_index, node->inst_cnt, node->rip);

finish:
    check_points[cpu->cpu_index] = node->next;
}
