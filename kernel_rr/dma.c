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

const char *kernel_rr_dma_log = "kernel_rr_dma.log";


__attribute_maybe_unused__ static rr_dma_entry *pending_dma_entry = NULL;

static rr_dma_entry *dma_entry_head = NULL;
static rr_dma_entry *dma_entry_cur = NULL;
__attribute_maybe_unused__ static int entry_cnt = 0;


__attribute_maybe_unused__ void rr_append_dma_sg(QEMUSGList *sg)
{
    int i, res;

    // if (entry_cnt > 1) {
    //     return;
    // }

    if (pending_dma_entry == NULL) {
        pending_dma_entry = (rr_dma_entry*)malloc(sizeof(rr_dma_entry));
        pending_dma_entry->len = 0;
        pending_dma_entry->next = NULL;
    }

    for (i = 0; i < sg->nsg; i++) {
        rr_sg_data *sgd = (rr_sg_data*)malloc(sizeof(rr_sg_data));
        uint8_t buf[sg->sg[i].len];

        sgd->buf = buf;

        if (sg->sg[i].len > 4096) {
            printf("DMA overflow size: %ld\n", sg->sg[i].len);
            // abort();
        }

        res = address_space_read(sg->as,
                                 sg->sg[i].base,
                                 MEMTXATTRS_UNSPECIFIED,
                                 sgd->buf, sg->sg[i].len);

        if (res != MEMTX_OK) {
            printf("failed to read from addr %d\n", res);
        } else {
            printf("read from dma base=0x%lx\n", sg->sg[i].base);
        }

        sgd->addr = sg->sg[i].base;
        sgd->len = sg->sg[i].len;

        pending_dma_entry->sgs[pending_dma_entry->len++] = sgd;
    }
}

static void append_dma_entry(rr_dma_entry *dma_entry)
{
    if (dma_entry_head == NULL) {
        dma_entry_head = dma_entry;
        dma_entry_cur = dma_entry;
    } else {
        dma_entry_cur->next = dma_entry;
        dma_entry_cur = dma_entry_cur->next;
    }

    dma_entry_cur->next = NULL;
}

__attribute_maybe_unused__ void rr_end_dma_entry(void)
{
    // if (entry_cnt > 1) {
    //     return;
    // }

    append_dma_entry(pending_dma_entry);
    pending_dma_entry = NULL;

    rr_signal_dma_finish();

    entry_cnt++;

    return;
}

static void persist_dma_buf(rr_sg_data *sg, FILE *fptr) {
    printf("Save sg len=%ld\n", sg->len);
    fwrite(sg->buf, sizeof(uint8_t), sg->len, fptr);
}

static void persist_dma_log(rr_dma_entry *log, FILE *fptr) {
    int i = 0;

    printf("Persist log entry, len=%d\n", log->len);

    fwrite(log, sizeof(rr_dma_entry), 1, fptr);

    for (i = 0; i < log->len; i++) {
	    fwrite(log->sgs[i], sizeof(rr_sg_data), 1, fptr);
        persist_dma_buf(log->sgs[i], fptr);
    }
}

static void rr_save_dma_logs(void)
{
	FILE *fptr = fopen(kernel_rr_dma_log, "a");
	rr_dma_entry *cur= dma_entry_head;

	while (cur != NULL) {
		persist_dma_log(cur, fptr);
        cur = cur->next;
	}

	fclose(fptr);
}

static void rr_load_dma_buf(uint8_t *buf, uint64_t len, FILE *fptr) {
    // int i = 0;
    // int data;
    printf("load buf for len=%ld\n", len);

    if (!fread(buf, sizeof(uint8_t), len, fptr)) {
        printf("Failed to read data\n");
        // printf("Read data index %d\n", i);
        // buf[i] = data;
        // i++;
    }
}

static void rr_load_dma_log(rr_dma_entry *log, FILE *fptr) {
    rr_sg_data loaded_sg;
    int i = 0;
    
    while(i < log->len && fread(&loaded_sg, sizeof(rr_sg_data), 1, fptr)) {
        rr_sg_data *sg = (rr_sg_data*)malloc(sizeof(rr_sg_data));
        uint8_t buf[loaded_sg.len];
        
        memcpy(sg, &loaded_sg, sizeof(rr_sg_data));

        rr_load_dma_buf(buf, sg->len, fptr);

        sg->buf = buf;
        log->sgs[i] = sg;
        i++;
    }
}

static void rr_load_dma_logs(void) {
	__attribute_maybe_unused__ FILE *fptr = fopen(kernel_rr_dma_log, "r");

    rr_dma_entry loaded_node;
    int i;

	while(fread(&loaded_node, sizeof(rr_dma_entry), 1, fptr)) {
        rr_dma_entry *log = (rr_dma_entry*)malloc(sizeof(rr_dma_entry));

        // memcpy(log, &loaded_node, sizeof(rr_dma_entry));
        log->len = loaded_node.len;

        printf("load entry: len=%d\n", log->len);

        rr_load_dma_log(log, fptr);

        for (i = 0; i < log->len; i++) {
            printf("log: sg_addr=0x%lx, sg_len=%ld\n", log->sgs[i]->addr, log->sgs[i]->len);
        }

		append_dma_entry(log);
	}
}

static void do_replay_dma_entry(rr_dma_entry *dma_entry)
{
    int i, res;

    for (i = 0; i < dma_entry->len; i++) {
        rr_sg_data *sg = dma_entry->sgs[i];
        

        res = address_space_write(&address_space_io,
                                  sg->addr,
                                  MEMTXATTRS_UNSPECIFIED,
                                  sg->buf, sg->len);

        if (res != MEMTX_OK) {
            if (res == MEMTX_ACCESS_ERROR) {
                printf("access is denied for addr=0x%lx\n", sg->addr);
            }
            printf("failed to write to mem: %d, addr=0x%lx\n", res, sg->addr);
        } else {
            printf("write to dma base=0x%lx\n", sg->addr);
        }
    }
}

void rr_dma_pre_record(void)
{
    remove(kernel_rr_dma_log);
}

void rr_dma_pre_replay(void)
{
    rr_load_dma_logs();
}

void rr_dma_post_record(void)
{
    rr_save_dma_logs();

    // while (dma_entry_head != NULL) {
    //     printf("DMA entry: %d\n", dma_entry_head->len);
    //     dma_entry_head = dma_entry_head->next;
    // }

    return;
}

void rr_replay_next_dma(void)
{
    do_replay_dma_entry(dma_entry_head);
    dma_entry_head = dma_entry_head->next;
}
