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

static unsigned long total_network_buf = 0;

// Currently not used
static rr_dma_queue* smp_entry_queue[MAX_CPU_NUM];

static int entry_cnt = 0;

static const char *network_log_name = "kernel_rr_network.log";

static void do_replay_network_dma_entry(rr_dma_entry *dma_entry)
{
    int i;

    if (dma_entry == NULL) {
        return;
    }

    qemu_log("Replay dma entry: inst=%lu, rip=0x%lx, follow_num=%lu, cpu_id=%d\n",
             dma_entry->inst_cnt, dma_entry->rip,
             dma_entry->follow_num, dma_entry->cpu_id);

    rr_sg_data *sg = dma_entry->sg_head;
    for (i = 0; i < dma_entry->len; i++) {
        uint64_t len = sg->len;

        qemu_log("Replay dma addr 0x%lx, len=%lu\n", sg->addr, len);
        printf("Replay dma addr 0x%lx\n", sg->addr);

        if (dma_memory_rw(e1000_as, sg->addr, sg->buf, len,
                      DMA_DIRECTION_FROM_DEVICE, MEMTXATTRS_UNSPECIFIED) != MEMTX_OK)
        {
            printf("Failed to write to dma addr\n");
            abort();
        } else {
            printf("Write to dma addr Ok\n");
        }
        sg = sg->next;
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
        pending_dma_entry->sg_head = NULL;
        pending_dma_entry->sg_tail = NULL;
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
    
    total_network_buf += len;
    // printf("data appended 0x%lx, len=%lu\n", sgd->addr, sgd->len);

    rr_dma_entry_append_sg(pending_dma_entry, sgd);
}

// This is currently not used
__attribute_maybe_unused__
static void rr_split_entry_queue(rr_dma_queue *queue)
{
    rr_dma_entry *front = dma_dequeue(queue);
    int i;

    for (i = 0; i < MAX_CPU_NUM; i++) {
        init_dma_queue(&smp_entry_queue[i]);
    }

    while (front != NULL) {
        if (front->cpu_id >= MAX_CPU_NUM) {
            printf("Invalid cpu_id %d\n", front->cpu_id);
            abort();
        }

        dma_enqueue(smp_entry_queue[front->cpu_id], front);
        front = dma_dequeue(queue);
    }
}

void rr_end_network_dma_entry(unsigned long inst_cnt, unsigned long rip, int cpu_id)
{
    if (pending_dma_entry == NULL)
        return;

    if (!pending_dma_entry->len) {
        return;
    }

    pending_dma_entry->replayed_sgs = 0;
    pending_dma_entry->inst_cnt = inst_cnt;
    pending_dma_entry->rip = rip;
    pending_dma_entry->follow_num = get_recorded_num();
    pending_dma_entry->cpu_id = cpu_id;

    // printf("Append new entry, len=%d\n", pending_dma_entry->len);
    dma_enqueue(dma_queue, pending_dma_entry);

    pending_dma_entry = NULL;

    entry_cnt++;

    return;
}

void rr_network_dma_post_record(void)
{
    rr_save_dma_logs(network_log_name, dma_queue->front);
    printf("network entry number %d, total net buf %lu\n",
           entry_cnt, total_network_buf);
}

void rr_network_dma_pre_record(void)
{
    init_dma_queue(&dma_queue);
    remove(network_log_name);

    total_network_buf = 0;
}

void rr_dma_network_pre_replay(void)
{
    rr_dma_pre_replay_common(network_log_name, &dma_queue, 0);

    // rr_split_entry_queue(dma_queue);
}


rr_dma_entry* rr_fetch_next_network_dme_entry(int cpu_id) 
{
    // return smp_entry_queue[cpu_id]->front;
    return dma_queue->front;
}


void rr_replay_next_network_dma(int cpu_id)
{
    rr_dma_entry *front;

    // front = dma_dequeue(smp_entry_queue[cpu_id]);
    front = dma_dequeue(dma_queue);
    if (front == NULL) {
        return;
    }

    do_replay_network_dma_entry(front);
}
