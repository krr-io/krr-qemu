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

const char *kernel_rr_dma_log = "kernel_rr_dma.log";
static AddressSpace *dma_as = NULL;


void rr_register_ide_as(IDEDMA *dma)
{
    if (dma_as != NULL) {
        return;
    }

    BMDMAState *bm = DO_UPCAST(BMDMAState, dma, dma);
    PCIDevice *pci_dev = PCI_DEVICE(bm->pci_dev);

    printf("Initialized dma address space\n");
    dma_as = pci_get_address_space(pci_dev);

    if (dma_as != NULL) {
        printf("initialized dma as\n");
    }
}

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
    pending_dma_entry->replayed_sgs = 0;

    append_dma_entry(pending_dma_entry);
    pending_dma_entry = NULL;

    entry_cnt++;

    return;
}

static void persist_dma_buf(rr_sg_data *sg, FILE *fptr) {
    sg->checksum = get_checksum(sg->buf, sg->len);

    printf("Save sg addr=0x%lx len=%ld, checksum=%lu\n", sg->addr, sg->len, sg->checksum);

    fwrite(sg, sizeof(rr_sg_data), 1, fptr);
    fwrite(sg->buf, sizeof(uint8_t), sg->len, fptr);
}

static void persist_dma_log(rr_dma_entry *log, FILE *fptr) {
    int i = 0;

    printf("Persist log entry, len=%d\n", log->len);

    fwrite(log, sizeof(rr_dma_entry), 1, fptr);

    for (i = 0; i < log->len; i++) {
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
    printf("load buf for len=%ld\n", len);

    if (!fread(buf, sizeof(uint8_t), len, fptr)) {
        printf("Failed to read data\n");
    }
}

static void rr_load_dma_log(rr_dma_entry *log, FILE *fptr) {
    rr_sg_data loaded_sg;
    int i = 0;
    unsigned long checksum;
    
    while(i < log->len && fread(&loaded_sg, sizeof(rr_sg_data), 1, fptr)) {
        rr_sg_data *sg = (rr_sg_data*)malloc(sizeof(rr_sg_data));
        uint8_t buf[loaded_sg.len];
        
        memcpy(sg, &loaded_sg, sizeof(rr_sg_data));

        rr_load_dma_buf(buf, sg->len, fptr);

        checksum = get_checksum(buf, sg->len);

        if (checksum != sg->checksum) {
            printf("Unmatched checksum of DMA data: %lu vs %lu\n", checksum, sg->checksum);
            abort();
        } else {
            printf("Checksum check passed for 0x%lx\n", sg->addr);
        }

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

        log->replayed_sgs = 0;

        for (i = 0; i < log->len; i++) {
            printf("log: sg_addr=0x%lx, sg_len=%ld\n", log->sgs[i]->addr, log->sgs[i]->len);
        }

		append_dma_entry(log);
	}
}

static void do_replay_dma_entry(rr_dma_entry *dma_entry)
{
    int i, res;
    void *mem;

    for (i = 0; i < dma_entry->len; i++) {
        rr_sg_data *sg = dma_entry->sgs[i];
        uint64_t len = sg->len;
        // uint8_t buf[sg->len + 1];

        printf("Replay dma addr 0x%lx\n", sg->addr);

        // buf[sg->len] = 0; 
        
        mem = dma_memory_map(dma_as,
                             sg->addr, &len,
                             DMA_DIRECTION_FROM_DEVICE,
                             MEMTXATTRS_UNSPECIFIED);

        if (!mem) {
             printf("failed to map addr 0x%lx\n", sg->addr);
             continue;
        }
        res = address_space_write(dma_as,
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


static void do_replay_dma_sg(rr_sg_data *dma_sg, AddressSpace *as)
{
    int res;

    printf("write to dma addr 0x%lx, len=%lu\n", dma_sg->addr, dma_sg->len);

    res = address_space_write(as,
                              dma_sg->addr,
                              MEMTXATTRS_UNSPECIFIED,
                              dma_sg->buf, dma_sg->len);


    if (res != MEMTX_OK) {
        if (res == MEMTX_ACCESS_ERROR) {
            printf("access is denied for addr=0x%lx\n", dma_sg->addr);
        }
        printf("failed to write to mem: %d, addr=0x%lx\n", res, dma_sg->addr);
    } else {
        printf("write to dma base=0x%lx\n", dma_sg->addr);
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
    return;
}

void rr_replay_next_dma(void)
{
    do_replay_dma_entry(dma_entry_head);
    dma_entry_head = dma_entry_head->next;

    if (rr_get_next_event_type() == EVENT_TYPE_DMA_DONE) {
        rr_pop_event_head();
        printf("Pop current dma event\n");
    }
}

void rr_check_dma_sg(ScatterGatherEntry sg, QEMUSGList *sgList)
{
    int i;
    rr_dma_entry *cur = NULL;

    if (dma_entry_head == NULL) {
        return;
    }

    cur = dma_entry_head;

    // while (cur != NULL) {
    for (i = 0; i < cur->len; i++) {
        if (cur->sgs[i]->addr == sg.base) {
            printf("found matched addr 0x%lx\n", sg.base);
            assert(cur->sgs[i]->len == sg.len);
            do_replay_dma_sg(cur->sgs[i], sgList->as);
            cur->replayed_sgs++;
            if (dma_entry_head->replayed_sgs == dma_entry_head->len) {
                dma_entry_head = dma_entry_head->next;
            }
            return;
        }
    }

    //     cur = cur->next;
    // }

    printf("Didn't find any addr: 0x%lx\n", sg.base);
}

void rr_set_trap(void)
{
    CPUState *cpu;
    CPU_FOREACH(cpu) {
        cpu->cause_debug = 1;
    }
}


void rr_get_dma_ctx(void)
{
    CPUState *cpu;
    X86CPU *x86_cpu;
    CPUArchState *env;

    CPU_FOREACH(cpu) {
        if (rr_in_record()) {
            kvm_cpu_synchronize_state(cpu);
        }
        x86_cpu = X86_CPU(cpu);
        env = &x86_cpu->env;

        qemu_log("Current RIP=0x%lx\n", env->eip);
    }
}
