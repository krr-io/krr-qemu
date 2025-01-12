#include "qemu/osdep.h"
#include "qemu/typedefs.h"

#include "sysemu/kernel-rr.h"
#include "cpu.h"

static int is_reverse_continue = 0;
static unsigned long temp_last_breakpoint_inst = 0;
static unsigned long last_breakpoint_inst = 0;

int is_reverse_bp_hit(CPUState *cpu)
{
    return get_total_executed_inst() == last_breakpoint_inst;
}

int is_in_reverse_continue(void)
{
    return is_reverse_continue;
}

void reset_in_reverse_continue(void)
{
    is_reverse_continue = 0;
}

void krr_note_breakpoint(CPUState *cpu)
{
    last_breakpoint_inst = temp_last_breakpoint_inst;
    temp_last_breakpoint_inst = get_total_executed_inst();
}

int krr_reverse_continue(void)
{
    int nearest_id = -1;
    CPUState *cpu;
    int current_owner = replay_get_current_owner();

    if (!last_breakpoint_inst) {
        printf("No breakpoint was hit before\n");
        return 0;
    }
    printf("reverse continuing\n");

    nearest_id = replay_find_nearest_snapshot(last_breakpoint_inst);
    if (nearest_id <= 0)
        return 0;

    CPU_FOREACH(cpu) {

        if (cpu->cpu_index == current_owner) {
            cpu->rr_break_inst = cpu->rr_executed_inst - 1;
            printf("Set break on %lu, current %lu\n", cpu->rr_break_inst, cpu->rr_executed_inst);
        }

        cpu->rr_break_inst = last_breakpoint_inst;
        restore_snapshot_by_id(nearest_id);
        printf("Set break on %lu, current %lu\n", cpu->rr_break_inst, cpu->rr_executed_inst);
    }

    is_reverse_continue = 1;

    return 1;
}

int krr_reverse_stepi(void)
{
    int nearest_id = -1;
    CPUState *cpu;
    int current_owner = replay_get_current_owner();

    printf("reverse stepping\n");

    nearest_id = replay_find_nearest_snapshot(get_total_executed_inst());
    if (nearest_id <= 0)
        return 0;

    CPU_FOREACH(cpu) {
        if (cpu->cpu_index == current_owner) {
            cpu->rr_break_inst = cpu->rr_executed_inst - 1;
            cpu->force_cal_eflags = 1;
            printf("Set break on CPU %d %lu, current %lu\n",
                   cpu->cpu_index, cpu->rr_break_inst, cpu->rr_executed_inst);
        } else {
            cpu->rr_break_inst = 0;
        }
    }

    restore_snapshot_by_id(nearest_id);

    is_reverse_continue = 1;

    return 1;
}
