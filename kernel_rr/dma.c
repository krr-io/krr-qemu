#include "qemu/osdep.h"
#include "qemu/typedefs.h"
#include "qemu-common.h"
#include "exec/log.h"
#include "migration/snapshot.h"
#include "sysemu/dma.h"
#include "hw/nvme/nvme.h"

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

#define DEV_IDE 0
#define DEV_NVME 1

#define MAX_DEV_NUM 8

const char *kernel_rr_dma_log = "kernel_rr_dma.log";

static bool kernel_only = true;
static bool record_net = true;

typedef struct rr_dma_stat_t {
    unsigned long total_buf_cnt;
    unsigned long total_buf_size;
} rr_dma_stat;

typedef struct rr_dma_dev_t {
    int dev_type;
    AddressSpace *as;
    PCIDevice *pdev;
    char *dev_id;
    int ignore;
    void *dma_cb;
    rr_dma_queue *dma_queue;
    rr_dma_entry *pending_dma_entry;
    int dev_index;
} rr_dma_dev;

typedef struct rr_dma_dev_manager_t {
    int dev_num;
    rr_dma_dev *dev_list[MAX_DEV_NUM];
    rr_dma_stat *stat;
} rr_dma_manager;

static rr_dma_manager *dma_manager = NULL;


void rr_init_dma(void)
{
    dma_manager = (rr_dma_manager *)malloc(sizeof(struct rr_dma_dev_manager_t));
    dma_manager->dev_num = 0;
    dma_manager->stat = (rr_dma_stat *)malloc(sizeof(struct rr_dma_stat_t));
    dma_manager->stat->total_buf_cnt = 0;
    dma_manager->stat->total_buf_size = 0;
}

static rr_dma_dev* lookup_dev_with_index(int dev_index)
{
    size_t i = 0;

    for (i = 0; i < dma_manager->dev_num; i++) {
        if (dma_manager->dev_list[i]->dev_index == dev_index) {
            return dma_manager->dev_list[i];
        }
    }

    return NULL;
}

static void register_dma_dev(PCIDevice *pci_dev, void *dma_cb, int dev_type)
{
    rr_dma_dev *rr_dev = (rr_dma_dev *)malloc(sizeof(struct rr_dma_dev_t));
    DeviceState *dev = DEVICE(pci_dev);

    if (lookup_dev_with_index(pci_dev->devfn) != NULL) {
        return;
    }

    rr_dev->as = pci_get_address_space(pci_dev);
    rr_dev->pdev = pci_dev;
    rr_dev->dev_id = g_strdup(dev->id);
    rr_dev->dma_cb = dma_cb;
    rr_dev->dev_index = pci_dev->devfn;
    rr_dev->dev_type = dev_type;
    rr_dev->dma_queue = NULL;

    dma_manager->dev_list[dma_manager->dev_num++] = rr_dev;

    LOG_MSG("Resgitered DMA device[%s] %d %u\n", pci_dev->name, rr_dev->dev_index, pci_dev->devfn);
}

static rr_dma_dev* lookup_dev_with_dma_cb(void *cb)
{
    uint8_t i;

    for (i = 0; i < dma_manager->dev_num; i++) {
        if (dma_manager->dev_list[i]->dma_cb == cb) {
            return dma_manager->dev_list[i];
        }
    }

    return NULL;
}

static rr_dma_dev* lookup_dev_with_pdev(PCIDevice *pdev)
{
    uint8_t i;

    for (i = 0; i < dma_manager->dev_num; i++) {
        if (dma_manager->dev_list[i]->pdev == pdev) {
            return dma_manager->dev_list[i];
        }
    }

    return NULL;
}

static rr_dma_dev* lookup_nvme_dev(void)
{
    uint8_t i;

    for (i = 0; i < dma_manager->dev_num; i++) {
        if (dma_manager->dev_list[i]->dev_type == DEV_TYPE_NVME) {
            return dma_manager->dev_list[i];
        }
    }

    return NULL;
}

unsigned long get_dma_buf_size(void)
{
    return dma_manager->stat->total_buf_size;
}

void rr_register_nvme_as(PCIDevice *dev, void *dma_cb)
{
    register_dma_dev(dev, dma_cb, DEV_TYPE_NVME);
}

void rr_register_ide_as(IDEDMA *dma, void *dma_cb)
{
    BMDMAState *bm = DO_UPCAST(BMDMAState, dma, dma);
    PCIDevice *pci_dev = PCI_DEVICE(bm->pci_dev);

    register_dma_dev(pci_dev, dma_cb, DEV_TYPE_IDE);
}

// static rr_dma_queue *dma_queue = NULL;
// __attribute_maybe_unused__ static rr_dma_entry *pending_dma_entry = NULL;
__attribute_maybe_unused__ static int entry_cnt = 0;

static void log_addr_md5(void *ptr, size_t len, dma_addr_t base)
{
    char md5_v[34];

    for (int j=0; j < len; j+=4096) {
        get_md5sum(ptr + j, 4096, md5_v);
        // qemu_log("md5 for dma addr 0x%lx %d is %s\n", base, j, md5_v);
    }
}


void rr_append_general_dma_sg(int dev_type, void *buf, uint64_t len, uint64_t addr)
{
    rr_sg_data *sgd = NULL;
    rr_dma_dev *dev = NULL;

    if (dev_type == DEV_TYPE_NVME) {
        dev = lookup_nvme_dev();
    } else {
        printf("No other device has been supported by rr_append_general_dma_sg\n");
        abort();
    }
    assert(dev != NULL);

    if (dev->pending_dma_entry == NULL) {
        dev->pending_dma_entry = (rr_dma_entry*)malloc(sizeof(rr_dma_entry));
        dev->pending_dma_entry->len = 0;
        dev->pending_dma_entry->next = NULL;
        dev->pending_dma_entry->dev_index = dev->dev_index;
    }

    if (dev->pending_dma_entry->len >= SG_NUM) {
        printf("Error: dma sg number exceeds max\n");
        free(sgd->buf);
        free(sgd);
        return;
    }

    if (dev->pending_dma_entry->len >= SG_NUM) {
        printf("Error: dma sg number exceeds max\n");
        return;
    }

    sgd = (rr_sg_data*)malloc(sizeof(rr_sg_data));
    sgd->buf = (uint8_t*)malloc(sizeof(uint8_t) * len);

    memcpy(sgd->buf, buf, len);
    sgd->addr = addr;
    sgd->len = len;
    
    dma_manager->stat->total_buf_size += len;
    dev->pending_dma_entry->sgs[dev->pending_dma_entry->len++] = sgd;
}

static PCIDevice* ide_get_pci_get_dev(void *opaque)
{
    IDEState *s = opaque;
    BMDMAState *bm = DO_UPCAST(BMDMAState, dma, s->bus->dma);
    PCIDevice *pdev = PCI_DEVICE(bm->pci_dev);

    return pdev;
}

void rr_append_dma_sg(QEMUSGList *sg, QEMUIOVector *qiov, void *cb, void *opaque)
{
    int i;
    __attribute_maybe_unused__ int res;
    rr_dma_dev *dev;
    rr_dma_entry *pending_dma_entry;
    PCIDevice *pdev = NULL;

    dev = lookup_dev_with_dma_cb(cb);

    switch (dev->dev_type)
    {
    case DEV_IDE:
        pdev = ide_get_pci_get_dev(opaque);
        break;
    case DEV_NVME:
        break;
    default:
        printf("DMA of unkown device type %d\n", dev->dev_type);
        abort();
    }

    if (pdev != NULL && pdev != dev->pdev) {
        /* TODO */
    }

    pending_dma_entry = dev->pending_dma_entry;

    if (pending_dma_entry == NULL) {
        pending_dma_entry = (rr_dma_entry*)malloc(sizeof(rr_dma_entry));
        pending_dma_entry->len = 0;
        pending_dma_entry->next = NULL;
        pending_dma_entry->dev_index = dev->dev_index;

        dev->pending_dma_entry = pending_dma_entry;
    }

    for (i = 0; i < sg->nsg; i++) {
        rr_sg_data *sgd = (rr_sg_data*)malloc(sizeof(rr_sg_data));
        sgd->buf = (uint8_t*)malloc(sizeof(uint8_t) * sg->sg[i].len);

        // if (sg->sg[i].len > 4096) {
        //     printf("DMA overflow size: %ld\n", sg->sg[i].len);
        //     // abort();
        // }

        res = address_space_read(sg->as,
                                 sg->sg[i].base,
                                 MEMTXATTRS_UNSPECIFIED,
                                 sgd->buf, sg->sg[i].len * sizeof(dma_data));
        if (res != MEMTX_OK) {
            printf("failed to read from addr %d\n", res);
        } 
        // else {
        //     printf("read from dma base=0x%lx\n", sg->sg[i].base);
        // }

        sgd->addr = sg->sg[i].base;
        sgd->len = sg->sg[i].len;

        if (pending_dma_entry->len >= SG_NUM) {
            printf("Error: dma sg number exceeds max\n");
            free(sgd->buf);
            free(sgd);
            return;
        }

        dma_manager->stat->total_buf_size += sg->sg[i].len;
        dma_manager->stat->total_buf_cnt++;

        pending_dma_entry->sgs[pending_dma_entry->len++] = sgd;

        assert(sg->sg[i].len == qiov->iov[i].iov_len);
    }
}

void rr_end_nvme_dma_entry(CPUState *cpu)
{
    rr_dma_dev *dev = lookup_nvme_dev();
    X86CPU *x86_cpu;
    CPUArchState *env;

    assert(dev != NULL);

    if (dev->pending_dma_entry == NULL)
        return;

    x86_cpu = X86_CPU(cpu);
    env = &x86_cpu->env;

    kvm_arch_get_registers(cpu);
    dev->pending_dma_entry->replayed_sgs = 0;
    dev->pending_dma_entry->dev_type = DEV_TYPE_NVME;
    dev->pending_dma_entry->cpu_id = cpu->cpu_index;
    dev->pending_dma_entry->inst_cnt = rr_get_inst_cnt(cpu);
    dev->pending_dma_entry->follow_num = get_recorded_num();
    dev->pending_dma_entry->rip = env->eip;

    dma_enqueue(dev->dma_queue, dev->pending_dma_entry);
    dev->pending_dma_entry = NULL;

    entry_cnt++;
}


void rr_end_ide_dma_entry(IDEDMA *dma)
{
    rr_dma_dev *dev;
    BMDMAState *bm = DO_UPCAST(BMDMAState, dma, dma);
    PCIDevice *pci_dev = PCI_DEVICE(bm->pci_dev);

    dev = lookup_dev_with_pdev(pci_dev);

    assert(dev != NULL);

    if (dev->pending_dma_entry == NULL)
        return;

    dev->pending_dma_entry->replayed_sgs = 0;
    dev->pending_dma_entry->dev_type = DEV_TYPE_IDE;

    dma_enqueue(dev->dma_queue, dev->pending_dma_entry);
    dev->pending_dma_entry = NULL;

    entry_cnt++;

    return;
}

static void persist_dma_buf(rr_sg_data *sg, FILE *fptr) {
    sg->checksum = get_checksum(sg->buf, sg->len);

    // printf("Save sg addr=0x%lx len=%ld, checksum=%lu\n", sg->addr, sg->len, sg->checksum);

    fwrite(sg, sizeof(rr_sg_data), 1, fptr);
    fwrite(sg->buf, sizeof(dma_data), sg->len, fptr);
}

static void persist_dma_log(rr_dma_entry *log, FILE *fptr) {
    int i = 0;

    // printf("Persist log entry, len=%d\n", log->len);

    fwrite(log, sizeof(rr_dma_entry), 1, fptr);

    qemu_log("Persist dm entry, inst cnt=%lu, cpu_id=%d\n",
             log->inst_cnt, log->cpu_id);

    for (i = 0; i < log->len; i++) {
        qemu_log("Persist log sg: 0x%lx\n", log->sgs[i]->addr);
        log_addr_md5(log->sgs[i]->buf, log->sgs[i]->len, log->sgs[i]->addr);
        persist_dma_buf(log->sgs[i], fptr);
    }
}

void rr_save_dma_logs(const char *log_name, rr_dma_entry *entry_head)
{
	FILE *fptr = fopen(log_name, "a");
	rr_dma_entry *cur= entry_head;
    int logged_entry = 0;

    if (entry_head == NULL) {
        printf("[%s] No dma entry generated\n", log_name);
        return;
    }

	while (cur != NULL) {
		persist_dma_log(cur, fptr);
        cur = cur->next;
        logged_entry++;
	}

    printf("[%s] Logged entry number %d\n", log_name, logged_entry);
	fclose(fptr);
}

void dma_enqueue(rr_dma_queue* q, rr_dma_entry *entry) {
    // If the queue is empty, then the new node is both front and rear
    if (q->rear == NULL) {
        q->front = q->rear = entry;
        return;
    }

    // Add the new node at the end of the queue and change rear
    q->rear->next = entry;
    q->rear = entry;
}

rr_dma_entry* dma_dequeue(rr_dma_queue* q) {
    if (q->front == NULL) {
        printf("Queue is empty\n");
        // rr_set_trap();

        return NULL; // or any other error code
    }

    rr_dma_entry* temp = q->front;
    q->front = q->front->next;

    // If the queue is now empty, update the rear pointer to NULL
    if (q->front == NULL) {
        q->rear = NULL;
    }

    return temp;
}

static void rr_load_dma_buf(dma_data *buf, uint64_t len, FILE *fptr) {
    // printf("load buf for len=%ld\n", len);

    if (!fread(buf, sizeof(dma_data), len, fptr)) {
        printf("Failed to read data\n");
    }
}

static void rr_load_dma_log(rr_dma_entry *log, FILE *fptr) {
    rr_sg_data loaded_sg;
    int i = 0;
    
    while(i < log->len && fread(&loaded_sg, sizeof(rr_sg_data), 1, fptr)) {
        rr_sg_data *sg = (rr_sg_data*)malloc(sizeof(rr_sg_data));        
        memcpy(sg, &loaded_sg, sizeof(rr_sg_data));

        sg->buf = (dma_data*)malloc(sizeof(dma_data) * loaded_sg.len);;

        rr_load_dma_buf(sg->buf, sg->len, fptr);

        log->sgs[i] = sg;
        i++;
    }
}

void rr_load_dma_logs(const char *log_file, rr_dma_queue *queue)
{
	__attribute_maybe_unused__ FILE *fptr = fopen(log_file, "r");

    rr_dma_entry loaded_node;
    // int i;

	while(fread(&loaded_node, sizeof(rr_dma_entry), 1, fptr)) {
        rr_dma_entry *log = (rr_dma_entry*)malloc(sizeof(rr_dma_entry));

        // memcpy(log, &loaded_node, sizeof(rr_dma_entry));
        log->len = loaded_node.len;

        // printf("load entry: len=%d\n", log->len);

        rr_load_dma_log(log, fptr);

        log->replayed_sgs = 0;
        log->inst_cnt = loaded_node.inst_cnt;
        log->rip = loaded_node.rip;
        log->follow_num = loaded_node.follow_num;
        log->cpu_id = loaded_node.cpu_id;
        log->dev_type = loaded_node.dev_type;
        log->dev_index = loaded_node.dev_index;
        log->next = NULL;

        qemu_log("Loaded DMA entry: len=%d inst_cnt=%lu, rip=0x%lx, follow_num=%lu, cpu_id=%d, dev_type=%d\n",
                 log->len, log->inst_cnt, log->rip, log->follow_num, log->cpu_id, log->dev_type);

        // for (i = 0; i < log->len; i++) {
        //     printf("log: sg_addr=0x%lx, sg_len=%ld\n", log->sgs[i]->addr, log->sgs[i]->len);
        // }

		dma_enqueue(queue, log);
	}
}

rr_dma_entry* rr_fetch_next_dma_entry(int dev_type)
{
    size_t i;
    unsigned long min_inst = ~0U;
    rr_dma_entry *next = NULL;
    unsigned long cur_inst;

    for (i = 0; i < dma_manager->dev_num; i++) {
        if (dma_manager->dev_list[i]->dev_type != dev_type)
            continue;

        if (dma_manager->dev_list[i]->dma_queue->front == NULL)
            continue;

        cur_inst = dma_manager->dev_list[i]->dma_queue->front->inst_cnt;
        if (cur_inst < min_inst) {
            next = dma_manager->dev_list[i]->dma_queue->front;
            min_inst = cur_inst;
        }
    }

    return next;
}

void do_replay_dma_entry(rr_dma_entry *dma_entry, AddressSpace *as)
{
    int i;
    int res;
    void *mem;

    if (dma_entry == NULL) {
        return;
    }

    printf("Replay dma entry, inst=%lu, dev_type=%d, cpu_id=%d\n",
           dma_entry->inst_cnt, dma_entry->dev_type, dma_entry->cpu_id);

    for (i = 0; i < dma_entry->len; i++) {
        rr_sg_data *sg = dma_entry->sgs[i];
        uint64_t len = sg->len;

        printf("Replay dma addr 0x%lx\n", sg->addr);

        mem = dma_memory_map(as,
                             sg->addr, &len,
                             DMA_DIRECTION_FROM_DEVICE,
                             MEMTXATTRS_UNSPECIFIED);
        if (!mem) {
             printf("failed to map addr 0x%lx\n", sg->addr);
             continue;
        }
        res = address_space_write(as,
                                sg->addr,
                                MEMTXATTRS_UNSPECIFIED,
                                sg->buf, sg->len * sizeof(dma_data));

        if (res != MEMTX_OK) {
            if (res == MEMTX_ACCESS_ERROR) {
                printf("access is denied for addr=0x%lx\n", sg->addr);
            }
            printf("failed to write to mem: %d, addr=0x%lx\n", res, sg->addr);
        } else {
            qemu_log("DMA_Replay: write to dma base=0x%lx, len=%ld\n", sg->addr, sg->len);
            printf("write to dma base=0x%lx, len=%ld\n", sg->addr, sg->len);
        }

        dma_memory_unmap(as, mem,
                         sg->len, DMA_DIRECTION_FROM_DEVICE,
                         sg->len);
    }
}

void init_dma_queue(rr_dma_queue **queue)
{
    assert(*queue == NULL);

    *queue = (rr_dma_queue *)malloc(sizeof(rr_dma_queue));
    (*queue)->front = NULL;
    (*queue)->rear = NULL;
}

void rr_dma_pre_record(void)
{
    size_t i = 0;
    printf("Reset dma sg buffer\n");
    dma_manager->stat->total_buf_cnt = 0;
    dma_manager->stat->total_buf_size = 0;

    for (i = 0; i < dma_manager->dev_num; i++) {
        init_dma_queue(&(dma_manager->dev_list[i]->dma_queue));
    }

    remove(kernel_rr_dma_log);
}

void rr_dma_pre_replay(void)
{
    size_t i = 0;
    char fname[32];

    for (i = 0; i < dma_manager->dev_num; i++) {
        sprintf(fname, "kernel_rr_dma-%d.log", dma_manager->dev_list[i]->dev_index);
        rr_dma_pre_replay_common(fname, &(dma_manager->dev_list[i]->dma_queue), dma_manager->dev_list[i]->dev_index);
    }
}

void rr_dma_pre_replay_common(const char *load_file, rr_dma_queue **queue, int dev_index)
{
    int entry_num = 0;

    init_dma_queue(queue);
    rr_dma_queue *q = *queue;

    rr_load_dma_logs(load_file, q);

    rr_dma_entry *cur = q->front;
    while (cur != NULL) {
        for (int i = 0; i < cur->len; i++) {
            log_addr_md5(cur->sgs[i]->buf, cur->sgs[i]->len, cur->sgs[i]->addr);
        }
        cur->dev_index = dev_index;

        cur = cur->next;
        entry_num++;
    }

    printf("dma entry number %d: %d\n", dev_index, entry_num);
}

void rr_dma_post_record(void)
{
    size_t i = 0;
    char fname[32];

    for (i = 0; i < dma_manager->dev_num; i++) {
        sprintf(fname, "kernel_rr_dma-%d.log", dma_manager->dev_list[i]->dev_index);
        remove(fname);
        rr_save_dma_logs(fname, dma_manager->dev_list[i]->dma_queue->front);
    }
    printf("Total dma buf cnt %lu size %lu\n",
           dma_manager->stat->total_buf_cnt,
           dma_manager->stat->total_buf_size);

    return;
}

void rr_do_replay_ide_dma(IDEDMA *dma)
{
    rr_dma_done e = {};
    BMDMAState *bm = DO_UPCAST(BMDMAState, dma, dma);
    PCIDevice *pci_dev = PCI_DEVICE(bm->pci_dev);
    rr_dma_dev *dev = lookup_dev_with_pdev(pci_dev);

    if (rr_get_next_event()->type == EVENT_TYPE_DMA_DONE) {
        append_to_queue(EVENT_TYPE_DMA_DONE, &e);
        rr_replay_next_dma(dev->dev_index);
        rr_pop_event_head();
    }
}

void rr_replay_next_dma(int dev_index)
{
    rr_dma_entry *front;
    rr_dma_dev *dev;

    dev = lookup_dev_with_index(dev_index);
    assert(dev != NULL);

    front = dma_dequeue(dev->dma_queue);
    if (front == NULL) {
        return;
    }

    LOG_MSG("Replay DMA entry, len=%d\n", front->len);
    do_replay_dma_entry(front, dev->as);
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

int get_kernel_only(void)
{
    return kernel_only;
}

void set_kernel_only(int konly)
{
    kernel_only = konly;
}

int get_record_net(void)
{
    return record_net;
}

void set_record_net(int val)
{
    record_net = val;
}
