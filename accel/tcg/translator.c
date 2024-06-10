/*
 * Generic intermediate code generation.
 *
 * Copyright (C) 2016-2017 Lluís Vilanova <vilanova@ac.upc.edu>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "linux-headers/linux/kernel_rr.h"
#include "sysemu/kernel-rr.h"

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "tcg/tcg.h"
#include "tcg/tcg-op.h"
#include "exec/exec-all.h"
#include "exec/gen-icount.h"
#include "exec/log.h"
#include "exec/translator.h"
#include "exec/plugin-gen.h"
#include "sysemu/replay.h"

#include "sysemu/kernel-rr.h"

/* Pairs with tcg_clear_temp_count.
   To be called by #TranslatorOps.{translate_insn,tb_stop} if
   (1) the target is sufficiently clean to support reporting,
   (2) as and when all temporaries are known to be consumed.
   For most targets, (2) is at the end of translate_insn.  */
void translator_loop_temp_check(DisasContextBase *db)
{
    if (tcg_check_temp_count()) {
        qemu_log("warning: TCG temporary leaks before "
                 TARGET_FMT_lx "\n", db->pc_next);
    }
}

bool translator_use_goto_tb(DisasContextBase *db, target_ulong dest)
{
    /* Suppress goto_tb if requested. */
    if (tb_cflags(db->tb) & CF_NO_GOTO_TB) {
        return false;
    }

    /* Check for the dest on the same page as the start of the TB.  */
    return ((db->pc_first ^ dest) & TARGET_PAGE_MASK) == 0;
}

static inline void translator_page_protect(DisasContextBase *dcbase,
                                           target_ulong pc)
{
#ifdef CONFIG_USER_ONLY
    dcbase->page_protect_end = pc | ~TARGET_PAGE_MASK;
    page_protect(pc);
#endif
}

void translator_loop(const TranslatorOps *ops, DisasContextBase *db,
                     CPUState *cpu, TranslationBlock *tb, int max_insns)
{
    uint32_t cflags = tb_cflags(tb);
    bool plugin_enabled;
    // X86CPU *x86_cpu;
    // CPUArchState *env;

    // x86_cpu = X86_CPU(cpu);
    // env = &x86_cpu->env;

    /* Initialize DisasContext */
    db->tb = tb;
    db->pc_first = tb->pc;
    db->pc_next = db->pc_first;
    db->is_jmp = DISAS_NEXT;
    db->num_insns = 0;
    db->max_insns = max_insns;
    db->singlestep_enabled = cflags & CF_SINGLE_STEP;
    translator_page_protect(db, db->pc_next);
    db->do_syscall = false;

    ops->init_disas_context(db, cpu);
    tcg_debug_assert(db->is_jmp == DISAS_NEXT);  /* no early exit */

    if (rr_in_replay() && db->in_user_mode) {
        qemu_log("[CPU %d]User mode, fetch next event\n", cpu->cpu_index);
// retry:
        rr_event_log *log = rr_get_next_event();
        int next_event = log->type;
        // uint64_t inst_cnt = log->inst_cnt;

        switch(next_event) {
            case EVENT_TYPE_SYSCALL:
                db->do_syscall = true;
                tb->jump_next_event = EVENT_TYPE_SYSCALL;
                qemu_log("Next event syscall\n");
                break;
            case EVENT_TYPE_INTERRUPT:
                tb->jump_next_event = EVENT_TYPE_INTERRUPT;
                // env->eip = rr_get_next_event_rip();
                break;
            case EVENT_TYPE_EXCEPTION:
                tb->jump_next_event = EVENT_TYPE_EXCEPTION;
                qemu_log("Next event exception\n");
                break;
            default:
                qemu_log("Unexpected next event %d, rip=0x%lx\n", next_event, log->rip);
                printf("Unexpected next event %d, rip=0x%lx\n", next_event, log->rip);
                // exit(1);
                // return;
                // rr_pop_event_head();s
                // goto retry;
                abort();
        }

        try_replay_dma(cpu, 1);
    }


    if (tb->jump_next_event == EVENT_TYPE_INTERRUPT || 
        tb->jump_next_event == EVENT_TYPE_EXCEPTION) {
        return;
    }

    /* Reset the temp count so that we can identify leaks */
    tcg_clear_temp_count();

    /* Start translating.  */
    gen_tb_start(db->tb);
    ops->tb_start(db, cpu);
    tcg_debug_assert(db->is_jmp == DISAS_NEXT);  /* no early exit */

    plugin_enabled = plugin_gen_tb_start(cpu, tb, cflags & CF_MEMI_ONLY);

    while (true) {
        db->num_insns++;
        ops->insn_start(db, cpu);
        tcg_debug_assert(db->is_jmp == DISAS_NEXT);  /* no early exit */

        if (plugin_enabled) {
            plugin_gen_insn_start(cpu, db);
        }

        if(rr_in_replay())
            gen_op_update_rr_icount();

        /* Disassemble one instruction.  The translate_insn hook should
           update db->pc_next and db->is_jmp to indicate what should be
           done next -- either exiting this loop or locate the start of
           the next instruction.  */
        if (db->num_insns == db->max_insns && (cflags & CF_LAST_IO)) {
            /* Accept I/O on the last instruction.  */
            gen_io_start();
            ops->translate_insn(db, cpu);
        } else {
            /* we should only see CF_MEMI_ONLY for io_recompile */
            tcg_debug_assert(!(cflags & CF_MEMI_ONLY));
            ops->translate_insn(db, cpu);
        }

        /* Stop translation if translate_insn so indicated.  */
        if (db->is_jmp != DISAS_NEXT) {
            break;
        }

        /*
         * We can't instrument after instructions that change control
         * flow although this only really affects post-load operations.
         */
        if (plugin_enabled) {
            plugin_gen_insn_end();
        }

        /* Stop translation if the output buffer is full,
           or we have executed all of the allowed instructions.  */
        if (tcg_op_buf_full() || db->num_insns >= db->max_insns) {
            db->is_jmp = DISAS_TOO_MANY;
            break;
        }
    }

    /* Emit code to exit the TB, as indicated by db->is_jmp.  */
    ops->tb_stop(db, cpu);
    gen_tb_end(db->tb, db->num_insns);

    if (plugin_enabled) {
        plugin_gen_tb_end(cpu);
    }

    /* The disas_log hook may use these values rather than recompute.  */
    tb->size = db->pc_next - db->pc_first;
    tb->icount = db->num_insns;
    tb->jump_next_event = -1;

    if (db->do_syscall) {
        tb->jump_next_event = EVENT_TYPE_SYSCALL;
    }

#ifdef DEBUG_DISAS
    if (qemu_loglevel_mask(CPU_LOG_TB_IN_ASM)
        && qemu_log_in_addr_range(db->pc_first)) {
        FILE *logfile = qemu_log_lock();
        qemu_log("Executed Inst: %lu\n", cpu->rr_guest_instr_count);
        qemu_log("----------------\n");
        ops->disas_log(db, cpu);
        qemu_log("\n");
        qemu_log_unlock(logfile);
    }
#endif
}

static inline void translator_maybe_page_protect(DisasContextBase *dcbase,
                                                 target_ulong pc, size_t len)
{
#ifdef CONFIG_USER_ONLY
    target_ulong end = pc + len - 1;

    if (end > dcbase->page_protect_end) {
        translator_page_protect(dcbase, end);
    }
#endif
}

#define GEN_TRANSLATOR_LD(fullname, type, load_fn, swap_fn)             \
    type fullname ## _swap(CPUArchState *env, DisasContextBase *dcbase, \
                           abi_ptr pc, bool do_swap)                    \
    {                                                                   \
        translator_maybe_page_protect(dcbase, pc, sizeof(type));        \
        type ret = load_fn(env, pc);                                    \
        if (do_swap) {                                                  \
            ret = swap_fn(ret);                                         \
        }                                                               \
        plugin_insn_append(pc, &ret, sizeof(ret));                      \
        return ret;                                                     \
    }

FOR_EACH_TRANSLATOR_LD(GEN_TRANSLATOR_LD)

#undef GEN_TRANSLATOR_LD
