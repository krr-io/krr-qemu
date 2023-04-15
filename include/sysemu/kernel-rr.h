#ifndef KERNEL_RR_H
#define KERNEL_RR_H

#include "qemu/typedefs.h"

int rr_in_replay(void);
void rr_set_replay(int replay, unsigned long ram_size);
void accel_start_kernel_replay(void);
void rr_replay_interrupt(CPUState *cpu, int *interrupt);

#endif /* KERNEL_RR_H */
