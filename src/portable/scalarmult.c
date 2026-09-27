/* Copyright (c) 2022 tevador <tevador@gmail.com>
 *
 * This file is part of mx25519, which is released under LGPLv3.
 * See LICENSE for full license details.
*/

#include "scalarmult.h"
#include "fe.h"

static NOINLINE void scalarmult(uint8_t* q,
    const uint8_t* e,
    const uint8_t* p)
{
    fe x1;
    fe x2;
    fe z2;
    fe x3;
    fe z3;
    fe tmp0;
    fe tmp1;
    int pos;
    volatile unsigned int swap;
    volatile unsigned int b;

    fe_frombytes(x1, p);
    fe_1(x2);
    fe_0(z2);
    fe_copy(x3, x1);
    fe_1(z3);

    swap = 0;
    for (pos = 254; pos >= 0; --pos) {
        b = (e[pos / 8] >> (pos & 7)) & 1;
        swap ^= b;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = b;
        fe_sub(tmp0, x3, z3);

        fe_sub(tmp1, x2, z2);
        fe_add(x2, x2, z2);
        fe_add(z2, x3, z3);

        fe_mul(z3, tmp0, x2);
        fe_mul(z2, z2, tmp1);
        fe_sq(tmp0, tmp1);
        fe_sq(tmp1, x2);
        fe_add(x3, z3, z2);
        fe_sub(z2, z3, z2);
        fe_mul(x2, tmp1, tmp0);
        fe_sub(tmp1, tmp1, tmp0);
        fe_sq(z2, z2);
        fe_mul121666(z3, tmp1);
        fe_sq(x3, x3);
        fe_add(tmp0, tmp0, z3);
        fe_mul(z3, x1, z2);
        fe_mul(z2, tmp1, tmp0);
    }
    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);

    fe_invert(z2, z2);
    fe_mul(x2, x2, z2);
    fe_tobytes(q, x2);

    /* clear the last key bit, works due to being a volatile store */
    swap = 0;
    b = 0;
}

/* "all", not "used": the registers to clear were set by scalarmult */
/* outside x86 and AArch64, some compilers crash on it or reject it */
#if defined(__i386) || defined(__x86_64__) || defined(__aarch64__)
#if defined(__has_attribute)
#if __has_attribute(zero_call_used_regs)
#define ZERO_CALL_USED_REGS __attribute__((zero_call_used_regs("all")))
#endif
#endif
#endif
#ifndef ZERO_CALL_USED_REGS
#define ZERO_CALL_USED_REGS
#endif

/* here, not on the caller: GCC skips the zeroing before a tail call */
static NOINLINE ZERO_CALL_USED_REGS void burn_stack(void)
{
    volatile uint64_t buf[512];
    size_t i;
    for (i = 0; i < sizeof(buf) / sizeof(buf[0]); ++i) {
        buf[i] = 0;
    }
}

void mx25519_scalarmult_portable(uint8_t* q,
    const uint8_t* e,
    const uint8_t* p)
{
    scalarmult(q, e, p);
    burn_stack();
}
