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

#define DEV_IDE 0;
#define DEV_NVME 1;

const char *kernel_rr_dma_log = "kernel_rr_dma.log";
static AddressSpace *dma_as = NULL;

void *nvme_cb_func = NULL;
static bool kernel_only = true;

static unsigned long total_buf_cnt = 0;
static unsigned long total_buf_size = 0;
static unsigned long total_nvme_cnt = 0;
static unsigned long total_nvme_size = 0;


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

static void log_addr_md5(void *ptr, size_t len, dma_addr_t base)
{
    char md5_v[34];

    for (int j=0; j < len; j+=4096) {
        get_md5sum(ptr + j, 4096, md5_v);
        // qemu_log("md5 for dma addr 0x%lx %d is %s\n", base, j, md5_v);
    }
}

__attribute_maybe_unused__ void rr_append_dma_sg(QEMUSGList *sg, QEMUIOVector *qiov, void *cb)
{
    int i;
    __attribute_maybe_unused__ int res;

    // if (entry_cnt > 1) {
    //     return;
    // }

    if (cb == nvme_cb_func && kernel_only)
        return; 

    if (pending_dma_entry == NULL) {
        pending_dma_entry = (rr_dma_entry*)malloc(sizeof(rr_dma_entry));
        pending_dma_entry->len = 0;
        pending_dma_entry->next = NULL;
    }

    for (i = 0; i < sg->nsg; i++) {
        rr_sg_data *sgd = (rr_sg_data*)malloc(sizeof(rr_sg_data));
        sgd->buf = (sg_addr*)malloc(sizeof(sg_addr) * sg->sg[i].len);

        // if (sg->sg[i].len > 4096) {
        //     printf("DMA overflow size: %ld\n", sg->sg[i].len);
        //     // abort();
        // }

        res = address_space_read(sg->as,
                                 sg->sg[i].base,
                                 MEMTXATTRS_UNSPECIFIED,
                                 sgd->buf, sg->sg[i].len * sizeof(sg_addr));
        if (res != MEMTX_OK) {
            printf("failed to read from addr %d\n", res);
        } 
        // else {
        //     printf("read from dma base=0x%lx\n", sg->sg[i].base);
        // }

        sgd->addr = sg->sg[i].base;
        sgd->len = sg->sg[i].len;

        total_buf_size += sg->sg[i].len;
        total_buf_cnt++;

        if (cb == nvme_cb_func) {
            total_nvme_size += sg->sg[i].len;
            total_nvme_cnt++;
            free(sgd->buf);
            free(sgd);
            return;
        }

        pending_dma_entry->sgs[pending_dma_entry->len++] = sgd;

        assert(sg->sg[i].len == qiov->iov[i].iov_len);
        // qemu_log("Get actual data:\n");
        // log_addr_md5(qiov->iov[i].iov_base, qiov->iov[i].iov_len, sg->sg[i].base);
        // qemu_log("Get logged data:\n");
        // log_addr_md5(sgd->buf, sg->sg[i].len, sg->sg[i].base);
    }
}

static void append_dma_entry(rr_dma_entry *dma_entry)
{
    if (dma_entry == NULL)
        return;

    if (dma_entry_head == NULL) {
        dma_entry_head = dma_entry;
        dma_entry_cur = dma_entry;
    } else {
        dma_entry_cur->next = dma_entry;
        dma_entry_cur = dma_entry_cur->next;
    }

    // qemu_log("Get logged data:\n");
    // for (int i=0; i < dma_entry_cur->len; i++) {
    //     log_addr_md5(dma_entry_cur->sgs[i]->buf, dma_entry_cur->sgs[i]->len, dma_entry_cur->sgs[i]->addr);
    // }

    dma_entry_cur->next = NULL;
}

__attribute_maybe_unused__ void rr_end_dma_entry(void)
{
    if (pending_dma_entry == NULL)
        return;

    pending_dma_entry->replayed_sgs = 0;

    append_dma_entry(pending_dma_entry);
    pending_dma_entry = NULL;

    entry_cnt++;

    return;
}

static void persist_dma_buf(rr_sg_data *sg, FILE *fptr) {
    sg->checksum = get_checksum(sg->buf, sg->len);

    // printf("Save sg addr=0x%lx len=%ld, checksum=%lu\n", sg->addr, sg->len, sg->checksum);

    fwrite(sg, sizeof(rr_sg_data), 1, fptr);
    fwrite(sg->buf, sizeof(sg_addr), sg->len, fptr);
}

static void persist_dma_log(rr_dma_entry *log, FILE *fptr) {
    int i = 0;

    // printf("Persist log entry, len=%d\n", log->len);

    fwrite(log, sizeof(rr_dma_entry), 1, fptr);

    for (i = 0; i < log->len; i++) {
        qemu_log("Persist log sg: 0x%lx\n", log->sgs[i]->addr);
        log_addr_md5(log->sgs[i]->buf, log->sgs[i]->len, log->sgs[i]->addr);
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

static void rr_load_dma_buf(sg_addr *buf, uint64_t len, FILE *fptr) {
    // printf("load buf for len=%ld\n", len);

    if (!fread(buf, sizeof(sg_addr), len, fptr)) {
        printf("Failed to read data\n");
    }
}

static void rr_load_dma_log(rr_dma_entry *log, FILE *fptr) {
    rr_sg_data loaded_sg;
    int i = 0;
    
    while(i < log->len && fread(&loaded_sg, sizeof(rr_sg_data), 1, fptr)) {
        rr_sg_data *sg = (rr_sg_data*)malloc(sizeof(rr_sg_data));        
        memcpy(sg, &loaded_sg, sizeof(rr_sg_data));

        sg->buf = (sg_addr*)malloc(sizeof(sg_addr) * loaded_sg.len);;

        rr_load_dma_buf(sg->buf, sg->len, fptr);

        log->sgs[i] = sg;
        i++;
    }
}

static void rr_load_dma_logs(void)
{
	__attribute_maybe_unused__ FILE *fptr = fopen(kernel_rr_dma_log, "r");

    rr_dma_entry loaded_node;
    // int i;

	while(fread(&loaded_node, sizeof(rr_dma_entry), 1, fptr)) {
        rr_dma_entry *log = (rr_dma_entry*)malloc(sizeof(rr_dma_entry));

        // memcpy(log, &loaded_node, sizeof(rr_dma_entry));
        log->len = loaded_node.len;

        // printf("load entry: len=%d\n", log->len);

        rr_load_dma_log(log, fptr);

        log->replayed_sgs = 0;

        // for (i = 0; i < log->len; i++) {
        //     printf("log: sg_addr=0x%lx, sg_len=%ld\n", log->sgs[i]->addr, log->sgs[i]->len);
        // }

		append_dma_entry(log);
	}
}

static void do_replay_dma_entry(rr_dma_entry *dma_entry)
{
    int i;
    int res;
    void *mem;

    if (dma_entry == NULL) {
        return;
    }

    for (i = 0; i < dma_entry->len; i++) {
        rr_sg_data *sg = dma_entry->sgs[i];
        uint64_t len = sg->len;
        // uint8_t buf[sg->len + 1];

        printf("Replay dma addr 0x%lx\n", sg->addr);

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
                                sg->buf, sg->len * sizeof(sg_addr));

        if (res != MEMTX_OK) {
            if (res == MEMTX_ACCESS_ERROR) {
                printf("access is denied for addr=0x%lx\n", sg->addr);
            }
            printf("failed to write to mem: %d, addr=0x%lx\n", res, sg->addr);
        } else {
            qemu_log("DMA_Replay: write to dma base=0x%lx, len=%ld\n", sg->addr, sg->len);
            printf("write to dma base=0x%lx, len=%ld\n", sg->addr, sg->len);
        }

        dma_memory_unmap(dma_as, mem,
                         sg->len, DMA_DIRECTION_FROM_DEVICE,
                         sg->len);
    }
}

void rr_dma_pre_record(void)
{
    printf("Reset dma sg buffer\n");
    total_buf_cnt = 0;
    total_buf_size = 0;
    total_nvme_cnt = 0;
    total_nvme_size = 0;
    remove(kernel_rr_dma_log);
}

void rr_dma_pre_replay(int dma_event_num)
{
    int entry_num = 0;

    rr_load_dma_logs();

    rr_dma_entry *cur = dma_entry_head;
    while (cur != NULL) {

        for (int i = 0; i < cur->len; i++) {
            log_addr_md5(cur->sgs[i]->buf, cur->sgs[i]->len, cur->sgs[i]->addr);
        }

        cur = cur->next;
        entry_num++;
    }

    // if (entry_num != dma_event_num) {
    //     printf("DMA entry number %d, dma event number %d, not equal\n", entry_num, dma_event_num);
    //     exit(1);
    // }

    printf("dma entry number: %d\n", entry_num);
}

void rr_dma_post_record(void)
{
    rr_save_dma_logs();
    printf("Total dma buf cnt %lu size %lu, total nvme buf cnt %lu size %lu\n",
           total_buf_cnt, total_buf_size, total_nvme_cnt, total_nvme_size);
    return;
}

void rr_replay_next_dma(void)
{
    if (dma_entry_head == NULL) {
        return;
    }

    do_replay_dma_entry(dma_entry_head);
    dma_entry_head = dma_entry_head->next;

    if (rr_get_next_event_type() == EVENT_TYPE_DMA_DONE) {
        rr_pop_event_head();
        printf("Pop current dma event\n");
    }
}

void rr_check_dma_sg(__attribute_maybe_unused__ ScatterGatherEntry sg,
                     __attribute_maybe_unused__ QEMUSGList *sgList)
{
    return;
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

void register_nvme_cb(void *func)
{
    printf("NVME cb is %p\n", func);
    nvme_cb_func = func;
}

__attribute_maybe_unused__
int skip_record_dma(void *cb_func)
{
    if (kernel_only && cb_func == nvme_cb_func)
        return 1;

    return 0;
}

void set_kernel_only(int konly)
{
    kernel_only = konly;
}
