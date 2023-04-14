#ifndef KERNEL_RR_H
#define KERNEL_RR_H

int rr_in_replay(void);
void rr_set_replay(int replay, unsigned long ram_size);
void accel_start_kernel_replay(void);

#endif /* KERNEL_RR_H */
