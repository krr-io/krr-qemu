#include "qemu/osdep.h"
#include "qemu/typedefs.h"
#include "qemu-common.h"
#include "exec/log.h"
#include "migration/snapshot.h"
#include "sysemu/dma.h"

#include "cpu.h"

#include "linux-headers/linux/kernel_rr.h"

#include "exec/memory.h"
#include "exec/address-spaces.h"

#include "sysemu/kernel-rr.h"
#include "accel/kvm/kvm-cpus.h"

#include "sysemu/kvm.h"
#include "exec/cpu-common.h"
#include "migration/ram.h"
#include "exec/ram_addr.h"
#include "migration/migration.h"
#include "qemu/main-loop.h"
#include "memory.h"
#include "hw/ide/pci.h"
#include "hw/ide/internal.h"

static rr_dma_queue *dma_queue = NULL;
static rr_dma_entry *pending_dma_entry = NULL;
static AddressSpace *e1000_as = NULL;

static int entry_cnt = 0;

static const char *network_log_name = "kernel_rr_network.log";

static void do_replay_network_dma_entry(rr_dma_entry *dma_entry)
{
    int i;

    if (dma_entry == NULL) {
        return;
    }

    for (i = 0; i < dma_entry->len; i++) {
        rr_sg_data *sg = dma_entry->sgs[i];
        uint64_t len = sg->len;

        qemu_log("Replay dma addr 0x%lx\n", sg->addr);
        printf("Replay dma addr 0x%lx\n", sg->addr);

        if (dma_memory_rw(e1000_as, sg->addr, sg->buf, len,
                      DMA_DIRECTION_FROM_DEVICE, MEMTXATTRS_UNSPECIFIED) != MEMTX_OK)
        {} else {
            printf("Write to dma addr Ok\n");
        }
    }
}

void rr_register_e1000_as(PCIDevice *dev)
{
    e1000_as = pci_get_address_space(dev);
    printf("Initialized e1000 addr space\n");
}


void rr_append_network_dma_sg(void *buf, uint64_t len, uint64_t addr)
{
    rr_sg_data *sgd = NULL;

    if (pending_dma_entry == NULL) {
        pending_dma_entry = (rr_dma_entry*)malloc(sizeof(rr_dma_entry));
        pending_dma_entry->len = 0;
        pending_dma_entry->next = NULL;
    }

    if (pending_dma_entry->len >= SG_NUM) {
        printf("Error: dma sg number exceeds max\n");
        free(sgd->buf);
        free(sgd);
        return;
    }

    if (pending_dma_entry->len >= SG_NUM) {
        printf("Error: dma sg number exceeds max\n");
        return;
    }

    sgd = (rr_sg_data*)malloc(sizeof(rr_sg_data));
    sgd->buf = (uint8_t*)malloc(sizeof(uint8_t) * len);

    memcpy(sgd->buf, buf, len);
    sgd->addr = addr;
    sgd->len = len;
    printf("data appended 0x%lx, len=%lu\n", sgd->addr, sgd->len);

    pending_dma_entry->sgs[pending_dma_entry->len++] = sgd;
}


void rr_end_network_dma_entry(void)
{
    if (pending_dma_entry == NULL)
        return;

    if (!pending_dma_entry->len) {
        return;
    }

    pending_dma_entry->replayed_sgs = 0;

    printf("Append new entry, len=%d\n", pending_dma_entry->len);
    dma_enqueue(dma_queue, pending_dma_entry);

    rr_signal_dma_finish();

    pending_dma_entry = NULL;

    entry_cnt++;

    return;
}

void rr_network_dma_post_record(void)
{
    rr_save_dma_logs(network_log_name, dma_queue->front);
    printf("network entry number %d\n", entry_cnt);
}

void rr_network_dma_pre_record(void)
{
    init_dma_queue(&dma_queue);
    remove(network_log_name);
}

void rr_dma_network_pre_replay(void)
{
    rr_dma_pre_replay_common(network_log_name, &dma_queue);
}

void rr_replay_next_network_dma(void)
{
    rr_dma_entry *front;

    front = dma_dequeue(dma_queue);
    if (front == NULL) {
        return;
    }

    do_replay_network_dma_entry(front);
}
