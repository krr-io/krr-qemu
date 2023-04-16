#ifndef KERNEL_RR_H
#define KERNEL_RR_H
#include <linux/kvm.h>
#include <sys/cdefs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdint.h>

#include "qemu/typedefs.h"


int rr_in_replay(void);
void rr_set_replay(int replay, unsigned long ram_size);
void accel_start_kernel_replay(void);

void rr_replay_interrupt(CPUState *cpu, int *interrupt);
void rr_do_replay_intno(CPUState *cpu, int *intno);

uint64_t rr_num_instr_before_next_interrupt(void);

#endif /* KERNEL_RR_H */
