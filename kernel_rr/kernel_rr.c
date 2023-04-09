#include <linux/kvm.h>
#include <sys/cdefs.h>

#include "sysemu/kernel-rr.h"

__attribute_maybe_unused__ static int g_rr_in_replay = 0;

int rr_in_replay(void)
{
    return g_rr_in_replay;
}

void rr_set_replay(int replay)
{
    g_rr_in_replay = replay;
    // printf("set kernel replay = %d\n", g_rr_in_replay);
}

void accel_start_kernel_replay(void)
{
    // kvm_start_record();
}
