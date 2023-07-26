#define OPENSSL_API_COMPAT 0x10100000L

#include<openssl/md5.h>

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "exec/log.h"
#include "migration/snapshot.h"

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


const char *kernel_rr_mem_log = "kernel_rr_mem.log";

rr_mem_log *rr_mem_log_head = NULL;
rr_mem_log *rr_mem_log_cur = NULL;

int total_check = 0;
int unpassed_check = 0;

static int mem_log_enabled = 0;


int rr_mem_logs_enabled(void)
{
    return mem_log_enabled;
}

void rr_enable_mem_logs(void)
{
    printf("memlog is enabled\n");
    mem_log_enabled = 1;
}

static void persist_mem_log(rr_mem_log *log, FILE *fptr) {
	fwrite(log, sizeof(rr_mem_log), 1, fptr);
}

static void rr_save_mem_logs(void)
{
	FILE *fptr = fopen(kernel_rr_mem_log, "a");
	rr_mem_log *cur= rr_mem_log_head;

	while (cur != NULL) {
		persist_mem_log(cur, fptr);
        cur = cur->next;
	}

	fclose(fptr);
}


unsigned long get_checksum(uint8_t *buffer, unsigned long buffersize)
{
    unsigned long ret = 0;

    for (int i = 0; i < buffersize; i++) {
        ret += buffer[i];
    }

    return ret;
}


int get_md5sum(void* buffer,
               unsigned long buffersize,
               char* checksum)
{

    MD5_CTX ctx;
    int rc,i;
    unsigned char digest[MD5_DIGEST_LENGTH];

    rc = MD5_Init(&ctx);
    if(rc != 1) {
        printf("error in get_md5sum : MD5_Init\n");
        return 1;
    }

    rc =  MD5_Update(&ctx,buffer,sizeof(int)*buffersize);
    if(rc != 1) {
        printf("error in get_md5sum : MD5_Update\n");
        return 1;
    }

    rc = MD5_Final(digest,&ctx);
    if(rc != 1) {
        printf("error in get_md5sum : MD5_Final\n");
        return 1;
    }

    for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
        snprintf(&(checksum[i*2]), 16*2, "%02x", (unsigned int)digest[i]);
    }

    checksum[2*MD5_DIGEST_LENGTH+1] = '\0';

    return 0;
}

rr_mem_log *rr_mem_log_new(void)
{
    rr_mem_log *mem_log = (rr_mem_log*)malloc(sizeof(rr_mem_log));
    return mem_log;
}

void append_mem_log(rr_mem_log *mem_log)
{
    if (rr_mem_log_cur == NULL) {
        rr_mem_log_head = mem_log;
        rr_mem_log_cur = mem_log;
    } else {
        rr_mem_log_cur->next = mem_log;
        rr_mem_log_cur = rr_mem_log_cur->next;
    }

    rr_mem_log_cur->next = NULL;
}

void rr_create_mem_log(int syscall, unsigned long gpa, unsigned long rip, unsigned long inst_cnt)
{
    hwaddr page;
    // char out[MD5_DIGEST_LENGTH * 2 + 2];
    int res;
    uint8_t *buf[TARGET_PAGE_SIZE];
    rr_mem_log *log = rr_mem_log_new();

    if (syscall >= 0) {
        log->syscall = syscall;
        append_mem_log(log);
        return;
    } else {
        log->syscall = -1;
    }

    page = gpa & TARGET_PAGE_MASK;

    res = address_space_read(&address_space_memory, page, MEMTXATTRS_UNSPECIFIED, buf, TARGET_PAGE_SIZE);

    if (res != MEMTX_OK) {
        printf("failed to read from addr 0x%lx\n", page);
    } else {
        get_md5sum(buf, TARGET_PAGE_SIZE, log->md5);

        log->gpa = page;
        log->rip = rip;
        log->inst_cnt = inst_cnt;

        printf("Read from addr 0x%lx\n", page);
        qemu_log("[mem_trace] gpa=0x%lx, rip=0x%lx, md5=%s\n", gpa, rip, log->md5);

        append_mem_log(log);
    }
}

void rr_memlog_post_record(void)
{
    rr_save_mem_logs();
}

void rr_memlog_post_replay(void)
{
    printf("Total checked mem addresses: %d, unpassed: %d\n", total_check, unpassed_check);
}

void rr_load_mem_logs(void) {
	__attribute_maybe_unused__ FILE *fptr = fopen(kernel_rr_mem_log, "r");

    rr_mem_log loaded_node;

	while(fread(&loaded_node, sizeof(rr_mem_log), 1, fptr)) {
        rr_mem_log *log = rr_mem_log_new();

        memcpy(log, &loaded_node, sizeof(rr_mem_log));

        if (log->syscall >= 0) {
            printf("[loaded mem_trace] Syscall: %d\n", log->syscall);
        } else {
            printf("[loaded mem_trace] gpa=0x%lx, rip=0x%lx, md5=%s\n", log->gpa, log->rip, log->md5);
        }
		append_mem_log(log);
	}
}

static void rr_pop_mem_log_head(void)
{
    rr_mem_log_head = rr_mem_log_head->next;
}

static void rr_check_gpa(rr_mem_log *log)
{
    char out[MD5_DIGEST_LENGTH * 2 + 2];
    int res;
    uint8_t *buf[TARGET_PAGE_SIZE];

    res = address_space_read(&address_space_memory, log->gpa, MEMTXATTRS_UNSPECIFIED, buf, TARGET_PAGE_SIZE);

    if (res != MEMTX_OK) {
        printf("failed to read from addr 0x%lx\n", log->gpa);
    } else {
        get_md5sum(buf, TARGET_PAGE_SIZE, out);

        if(strcmp(log->md5, out) != 0) {
            unpassed_check++;
            qemu_log("gpa 0x%lx is not consistent, expected: %s, actual: %s, rip=0x%lx\n",
                     log->gpa, log->md5, out, log->rip);
        } else {
            qemu_log("gpa 0x%lx passed\n", log->gpa);
        }

        total_check++;
    }
}

void rr_verify_dirty_mem(CPUState *cpu)
{
    assert(rr_mem_log_head->syscall >= 0);
    
    rr_pop_mem_log_head();

    while (rr_mem_log_head != NULL && rr_mem_log_head->syscall == -1 && cpu->rr_executed_inst) {
        qemu_log("Check gpa 0x%lx\n", rr_mem_log_head->gpa);
        rr_check_gpa(rr_mem_log_head);
        rr_pop_mem_log_head();
    }
}

void rr_pre_mem_record(void)
{
    remove(kernel_rr_mem_log);
}
