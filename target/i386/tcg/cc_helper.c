/*
 *  x86 condition code helpers
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "helper-tcg.h"
#include "sysemu/kernel-rr.h"
#include "exec/log.h"

const uint8_t parity_table[256] = {
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
};

#define SHIFT 0
#include "cc_helper_template.h"
#undef SHIFT

#define SHIFT 1
#include "cc_helper_template.h"
#undef SHIFT

#define SHIFT 2
#include "cc_helper_template.h"
#undef SHIFT

#ifdef TARGET_X86_64

#define SHIFT 3
#include "cc_helper_template.h"
#undef SHIFT

#endif

static target_ulong compute_all_adcx(target_ulong dst, target_ulong src1,
                                     target_ulong src2)
{
    return (src1 & ~CC_C) | (dst * CC_C);
}

static target_ulong compute_all_adox(target_ulong dst, target_ulong src1,
                                     target_ulong src2)
{
    return (src1 & ~CC_O) | (src2 * CC_O);
}

static target_ulong compute_all_adcox(target_ulong dst, target_ulong src1,
                                      target_ulong src2)
{
    return (src1 & ~(CC_C | CC_O)) | (dst * CC_C) | (src2 * CC_O);
}

int is_valid_op(int op)
{
    switch(op) {
        case CC_OP_EFLAGS:
        case CC_OP_CLR:
        case CC_OP_POPCNT:
        case CC_OP_MULB:
        case CC_OP_MULW:
        case CC_OP_MULL:
        case CC_OP_ADDB:
        case CC_OP_ADDW:
        case CC_OP_ADDL:
        case CC_OP_ADCB:
        case CC_OP_ADCW:
        case CC_OP_ADCL:
        case CC_OP_SUBB:
        case CC_OP_SUBW:
        case CC_OP_SUBL:
        case CC_OP_SBBB:
        case CC_OP_SBBW:
        case CC_OP_SBBL:
        case CC_OP_LOGICB:
        case CC_OP_LOGICW:
        case CC_OP_LOGICL:
        case CC_OP_INCB:
        case CC_OP_INCW:
        case CC_OP_INCL:
        case CC_OP_DECB:
        case CC_OP_DECW:
        case CC_OP_DECL:
        case CC_OP_SHLB:
        case CC_OP_SHLW:
        case CC_OP_SHLL:
        case CC_OP_SARB:
        case CC_OP_SARW:
        case CC_OP_SARL:
        case CC_OP_BMILGB:
        case CC_OP_BMILGW:
        case CC_OP_BMILGL:
        case CC_OP_ADCX:
        case CC_OP_ADOX:
        case CC_OP_ADCOX:
        case CC_OP_SHRB:
        case CC_OP_SHRW:
        case CC_OP_SHRL:
        case CC_OP_SHRDB:
        case CC_OP_SHRDW:
        case CC_OP_SHRDL:
        case CC_OP_BSRB:
        case CC_OP_BSRW:
        case CC_OP_BSRL:
#ifdef TARGET_X86_64
        case CC_OP_MULQ:
        case CC_OP_ADDQ:
        case CC_OP_ADCQ:
        case CC_OP_SUBQ:
        case CC_OP_SBBQ:
        case CC_OP_LOGICQ:
        case CC_OP_INCQ:
        case CC_OP_DECQ:
        case CC_OP_SHLQ:
        case CC_OP_SARQ:
        case CC_OP_BMILGQ:
        case CC_OP_SHRQ:
        case CC_OP_SHRDQ:
        case CC_OP_BSRQ:
#endif
            return 1;
        default:
            return 0;
    }

    return 0;
}


target_ulong helper_cc_compute_all(target_ulong dst, target_ulong src1,
                                   target_ulong src2, int op)
{
    // qemu_log("op=%d, src1=%lx src2=%lx\n", op, src1, src2);
    switch (op) {
    default: /* should never happen */
        return 0;

    case CC_OP_EFLAGS:
        return src1;
    case CC_OP_CLR:
        return CC_Z | CC_P;
    case CC_OP_POPCNT:
        return src1 ? 0 : CC_Z;

    case CC_OP_MULB:
        return compute_all_mulb(dst, src1);
    case CC_OP_MULW:
        return compute_all_mulw(dst, src1);
    case CC_OP_MULL:
        return compute_all_mull(dst, src1);

    case CC_OP_ADDB:
        return compute_all_addb(dst, src1);
    case CC_OP_ADDW:
        return compute_all_addw(dst, src1);
    case CC_OP_ADDL:
        return compute_all_addl(dst, src1);

    case CC_OP_ADCB:
        return compute_all_adcb(dst, src1, src2);
    case CC_OP_ADCW:
        return compute_all_adcw(dst, src1, src2);
    case CC_OP_ADCL:
        return compute_all_adcl(dst, src1, src2);

    case CC_OP_SUBB:
        return compute_all_subb(dst, src1);
    case CC_OP_SUBW:
        return compute_all_subw(dst, src1);
    case CC_OP_SUBL:
        return compute_all_subl(dst, src1);

    case CC_OP_SBBB:
        return compute_all_sbbb(dst, src1, src2);
    case CC_OP_SBBW:
        return compute_all_sbbw(dst, src1, src2);
    case CC_OP_SBBL:
        return compute_all_sbbl(dst, src1, src2);

    case CC_OP_LOGICB:
        return compute_all_logicb(dst, src1);
    case CC_OP_LOGICW:
        return compute_all_logicw(dst, src1);
    case CC_OP_LOGICL:
        return compute_all_logicl(dst, src1);

    case CC_OP_INCB:
        return compute_all_incb(dst, src1);
    case CC_OP_INCW:
        return compute_all_incw(dst, src1);
    case CC_OP_INCL:
        return compute_all_incl(dst, src1);

    case CC_OP_DECB:
        return compute_all_decb(dst, src1);
    case CC_OP_DECW:
        return compute_all_decw(dst, src1);
    case CC_OP_DECL:
        return compute_all_decl(dst, src1);

    case CC_OP_SHLB:
        return compute_all_shlb(dst, src1, src2);
    case CC_OP_SHLW:
        return compute_all_shlw(dst, src1, src2);
    case CC_OP_SHLL:
        return compute_all_shll(dst, src1, src2);

    case CC_OP_SARB:
        return compute_all_sarb(dst, src1);
    case CC_OP_SARW:
        return compute_all_sarw(dst, src1);
    case CC_OP_SARL:
        return compute_all_sarl(dst, src1);

    case CC_OP_BMILGB:
        return compute_all_bmilgb(dst, src1);
    case CC_OP_BMILGW:
        return compute_all_bmilgw(dst, src1);
    case CC_OP_BMILGL:
        return compute_all_bmilgl(dst, src1);

    case CC_OP_ADCX:
        return compute_all_adcx(dst, src1, src2);
    case CC_OP_ADOX:
        return compute_all_adox(dst, src1, src2);
    case CC_OP_ADCOX:
        return compute_all_adcox(dst, src1, src2);

    case CC_OP_SHRB:
        return compute_all_shrb(dst, src1, src2);
    case CC_OP_SHRW:
        return compute_all_shrw(dst, src1, src2);
    case CC_OP_SHRL:
        return compute_all_shrl(dst, src1, src2);

    case CC_OP_SHRDB:
        return compute_all_shrdb(dst, src1, src2);
    case CC_OP_SHRDW:
        return compute_all_shrdw(dst, src1, src2);
    case CC_OP_SHRDL:
        return compute_all_shrdl(dst, src1, src2);

    case CC_OP_BSRB:
        return compute_all_bsrb(dst, src1);
    case CC_OP_BSRW:
        return compute_all_bsrw(dst, src1);
    case CC_OP_BSRL:
        return compute_all_bsrl(dst, src1);

#ifdef TARGET_X86_64
    case CC_OP_MULQ:
        return compute_all_mulq(dst, src1);
    case CC_OP_ADDQ:
        return compute_all_addq(dst, src1);
    case CC_OP_ADCQ:
        return compute_all_adcq(dst, src1, src2);
    case CC_OP_SUBQ:
        return compute_all_subq(dst, src1);
    case CC_OP_SBBQ:
        return compute_all_sbbq(dst, src1, src2);
    case CC_OP_LOGICQ:
        return compute_all_logicq(dst, src1);
    case CC_OP_INCQ:
        return compute_all_incq(dst, src1);
    case CC_OP_DECQ:
        return compute_all_decq(dst, src1);
    case CC_OP_SHLQ:
        return compute_all_shlq(dst, src1, src2);
    case CC_OP_SARQ:
        return compute_all_sarq(dst, src1);
    case CC_OP_SHRQ:
        return compute_all_shrq(dst, src1, src2);
    case CC_OP_SHRDQ:
        return compute_all_shrdq(dst, src1, src2);
    case CC_OP_BSRQ:
        return compute_all_bsrq(dst, src1);
    case CC_OP_BMILGQ:
        return compute_all_bmilgq(dst, src1);
#endif
    }
}

uint32_t cpu_cc_compute_all(CPUX86State *env, int op)
{
    return helper_cc_compute_all(CC_DST, CC_SRC, CC_SRC2, op);
}

target_ulong helper_cc_compute_c(target_ulong dst, target_ulong src1,
                                 target_ulong src2, int op)
{
    switch (op) {
    default: /* should never happen */
    case CC_OP_LOGICB:
    case CC_OP_LOGICW:
    case CC_OP_LOGICL:
    case CC_OP_LOGICQ:
    case CC_OP_CLR:
    case CC_OP_POPCNT:
        return 0;

    case CC_OP_EFLAGS:
    case CC_OP_SARB:
    case CC_OP_SARW:
    case CC_OP_SARL:
    case CC_OP_SARQ:
    case CC_OP_ADOX:
        return src1 & 1;

    case CC_OP_INCB:
    case CC_OP_INCW:
    case CC_OP_INCL:
    case CC_OP_INCQ:
    case CC_OP_DECB:
    case CC_OP_DECW:
    case CC_OP_DECL:
    case CC_OP_DECQ:
        return src1;

    case CC_OP_MULB:
    case CC_OP_MULW:
    case CC_OP_MULL:
    case CC_OP_MULQ:
        return src1 != 0;

    case CC_OP_ADCX:
    case CC_OP_ADCOX:
        return dst;

    case CC_OP_ADDB:
        return compute_c_addb(dst, src1);
    case CC_OP_ADDW:
        return compute_c_addw(dst, src1);
    case CC_OP_ADDL:
        return compute_c_addl(dst, src1);

    case CC_OP_ADCB:
        return compute_c_adcb(dst, src1, src2);
    case CC_OP_ADCW:
        return compute_c_adcw(dst, src1, src2);
    case CC_OP_ADCL:
        return compute_c_adcl(dst, src1, src2);

    case CC_OP_SUBB:
        return compute_c_subb(dst, src1);
    case CC_OP_SUBW:
        return compute_c_subw(dst, src1);
    case CC_OP_SUBL:
        return compute_c_subl(dst, src1);

    case CC_OP_SBBB:
        return compute_c_sbbb(dst, src1, src2);
    case CC_OP_SBBW:
        return compute_c_sbbw(dst, src1, src2);
    case CC_OP_SBBL:
        return compute_c_sbbl(dst, src1, src2);

    case CC_OP_SHLB:
        return compute_c_shlb(dst, src1);
    case CC_OP_SHLW:
        return compute_c_shlw(dst, src1);
    case CC_OP_SHLL:
        return compute_c_shll(dst, src1);

    case CC_OP_BMILGB:
        return compute_c_bmilgb(dst, src1);
    case CC_OP_BMILGW:
        return compute_c_bmilgw(dst, src1);
    case CC_OP_BMILGL:
        return compute_c_bmilgl(dst, src1);

#ifdef TARGET_X86_64
    case CC_OP_ADDQ:
        return compute_c_addq(dst, src1);
    case CC_OP_ADCQ:
        return compute_c_adcq(dst, src1, src2);
    case CC_OP_SUBQ:
        return compute_c_subq(dst, src1);
    case CC_OP_SBBQ:
        return compute_c_sbbq(dst, src1, src2);
    case CC_OP_SHLQ:
        return compute_c_shlq(dst, src1);
    case CC_OP_BMILGQ:
        return compute_c_bmilgq(dst, src1);
#endif
    }
}

void helper_rr_write_eflags(CPUX86State *env, target_ulong t0,
                         uint32_t update_mask)
{
    if (!is_valid_op(env->cc_op)) {
        // qemu_log("invalid cc op %d\n", env->cc_op);
        return;
    }

    // qemu_log("valid cc op %d\n", env->cc_op);
    cpu_load_eflags(env, t0, update_mask);
}

void helper_write_eflags(CPUX86State *env, target_ulong t0,
                         uint32_t update_mask)
{
    cpu_load_eflags(env, t0, update_mask);
}

target_ulong helper_read_eflags(CPUX86State *env)
{
    uint32_t eflags;

    eflags = cpu_cc_compute_all(env, CC_OP);
    eflags |= (env->df & DF_MASK);
    eflags |= env->eflags & ~(VM_MASK | RF_MASK);
    // eflags |= TF_MASK;
    return eflags;
}

void helper_clts(CPUX86State *env)
{
    env->cr[0] &= ~CR0_TS_MASK;
    env->hflags &= ~HF_TS_MASK;
}

void helper_reset_rf(CPUX86State *env)
{
    env->eflags &= ~RF_MASK;
}

void helper_cli(CPUX86State *env)
{
    env->eflags &= ~IF_MASK;
}

void helper_sti(CPUX86State *env)
{
    env->eflags |= IF_MASK;
}

void helper_clac(CPUX86State *env)
{
    env->eflags &= ~AC_MASK;
}

void helper_stac(CPUX86State *env)
{
    env->eflags |= AC_MASK;
}

#if 0
/* vm86plus instructions */
void helper_cli_vm(CPUX86State *env)
{
    env->eflags &= ~VIF_MASK;
}

void helper_sti_vm(CPUX86State *env)
{
    env->eflags |= VIF_MASK;
    if (env->eflags & VIP_MASK) {
        raise_exception_ra(env, EXCP0D_GPF, GETPC());
    }
}
#endif
