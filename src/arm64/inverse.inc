/* Copyright (c) 2021-2026 tevador <tevador@gmail.com>
 *
 * This file is part of mx25519, which is released under LGPLv3.
 * See LICENSE for full license details.
*/

/*
 * Constant-time modular inversion mod 2^255-19 by the "safegcd" (Bernstein-
 * Yang) algorithm, scheduled for Cortex-A53.
 *
 * Calling convention:
 *
 *     x0 = pointer to the 32-byte little-endian input (may be unreduced)
 *     x1 = pointer to the 32-byte little-endian output (fully reduced)
 *
 * The input and output may be the same address. inv(0) = 0.
 * Clobbers x0-x17 and v0-v31 except d8-d15. Uses 544 bytes of stack, which
 * is zeroed before returning.
 */

#if defined(__APPLE__)
#define PAGE(x) x@PAGE
#define PAGEOFF(x) x@PAGEOFF
#else
#define PAGE(x) x
#define PAGEOFF(x) :lo12:x
#endif

#if defined(__APPLE__)
    .section __TEXT,__const
#elif defined(_WIN32)
    .section .rdata,"dr"
#else
    .section .rodata
#endif
    .balign  16
.Lgcd_table:
    .quad    19, 19, 19, 19
    .quad    0, 19, 0, 19
    .quad    -1, 32767, -1, 32767
    .quad    678152731, 678152731, 678152731, 678152731
    .quad    0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF
    .quad    0x200000000, 0x200000000, 0x200000000, 0x200000000
    .quad    0x1000000000000, 0x1000000000000, 0x1000000000000, 0x1000000000000
    .quad    0x8000000000000000, 0x8000000000000000, 0x8000000000000000, 0x8000000000000000
    .quad    0x7FFFFFFE00000000, 0x7FFFFFFE00000000, 0x7FFFFFFE00000000, 0x7FFFFFFE00000000
    .quad    -19, 0, 0, 0x3ffffff8
    .quad    0, 0, 0, 0x3fffffff
    .quad    0, 0, 0, 0x3fffffff
    .quad    0, 0, 0, 0x3fffffff
    .quad    0, 0, 0, 0x3fffffff
    .quad    0, 0, 0, 0x3fffffff
    .quad    0, 0, 0, 0x250d7fff
    .quad    0, 0, 0, 0x035e50d7
    .quad    32768, 0, 0, 0x000035e5

    .text
.p2align 4

.Linv25519:

    sub    sp, sp, #544
    stp    d8, d9, [sp, #0]
    stp    d10, d11, [sp, #16]
    stp    d12, d13, [sp, #32]
    stp    d14, d15, [sp, #48]
    stp    x19, x28, [sp, #64]
    stp    x29, x30, [sp, #80]
    add    x29, sp, #80
    str    x1, [sp, #536]
    adrp   x2, PAGE(.Lgcd_table)
    add    x2, x2, PAGEOFF(.Lgcd_table)

    ldp    x6, x7, [x0, #16]
    mov    x28, #19
    ldp    x4, x5, [x0, #0]
    add    x19, sp, #496
    ldr    q11, [x2, #304]
    mov    x10, #0x1000000000000000
    mov    x3, x7
    mov    x0, x2 /* x0 = .Lgcd_table */
    asr    x3, x3, #63
    bic    x7, x7, 0x8000000000000000
    ldr    q10, [x2, #288]
    mov    x8, #10
    and    x3, x3, x28
    eor    x11, x11, x11
    add    x3, x3, x28
    str    q11, [sp, #128]
    adds   x4, x4, x3
    mov    x12, x10
    adcs   x5, x5, xzr
    str    q10, [sp, #112]
    adcs   x6, x6, xzr
    eor    x13, x13, x13
    adc    x7, x7, xzr
    mov    x14, #-1
    mov    x3, x7
    mov    x15, #-1
    asr    x3, x3, #63
    bic    x7, x7, 0x8000000000000000
    and    x3, x3, x28
    adds   x4, x4, x3
    subs   x4, x4, x28
    mov    x3, x4
    sbcs   x5, x5, xzr
    and    x3, x3, 0x3fffffff
    bic    x9, x4, 0xf000000000000000
    str    x3, [sp, #128]
    sbcs   x6, x6, xzr
    ldr    q11, [x2, #336]
    mov    x3, x4
    lsr    x3, x3, #30
    lsr    x4, x4, #60
    ldr    q10, [x2, #320]
    sbc    x7, x7, xzr
    and    x3, x3, 0x3fffffff
    str    q11, [sp, #160]
    str    x3, [sp, #160]
    str    q10, [sp, #144]
    mov    x3, x5
    lsl    x3, x3, #4
    ldr    q11, [x2, #368]
    orr    x4, x3, x4
    ldr    q10, [x2, #352]
    and    x4, x4, 0x3fffffff
    mov    x3, x6
    str    q11, [sp, #192]
    lsl    x3, x3, #8
    str    q10, [sp, #176]
    str    x4, [sp, #192]
    ldr    q11, [x2, #400]
    mov    x4, x5
    lsr    x4, x4, #26
    lsr    x5, x5, #56
    ldr    q10, [x2, #384]
    and    x4, x4, 0x3fffffff
    orr    x5, x3, x5
    str    q11, [sp, #224]
    and    x5, x5, 0x3fffffff
    mov    x3, x7
    str    q10, [sp, #208]
    lsl    x3, x3, #12
    str    x4, [sp, #224]
    ldr    q11, [x2, #432]
    mov    x4, x6
    lsr    x4, x4, #22
    lsr    x6, x6, #52
    ldr    q10, [x2, #416]
    and    x4, x4, 0x3fffffff
    orr    x6, x3, x6
    str    q11, [sp, #256]
    and    x6, x6, 0x3fffffff
    str    q10, [sp, #240]
    str    x5, [sp, #256]
    ldr    q11, [x2, #464]
    ldr    q10, [x2, #448]
    str    q11, [sp, #288]
    str    q10, [sp, #272]
    str    x4, [sp, #288]
    ldr    q11, [x2, #496]
    mov    x4, x7
    lsr    x4, x4, #18
    lsr    x7, x7, #48
    ldr    q10, [x2, #480]
    and    x4, x4, 0x3fffffff
    str    q11, [sp, #320]
    str    q10, [sp, #304]
    str    x6, [sp, #320]
    ldr    q11, [x2, #528]
    mov    x6, #-0x4000000000000000
    ldr    q10, [x2, #512]
    str    q11, [sp, #352]
    str    q10, [sp, #336]
    str    x4, [sp, #352]
    ldr    q11, [x2, #560]
    eor    x4, x4, x4
    ldr    q10, [x2, #544]
    str    q11, [sp, #384]
    str    q10, [sp, #368]
    mov    x5, #0x100000
    str    x7, [sp, #384]
    stp    x6, x5, [x19, #0]
    mov    x7, #-19
    mov    x6, #-0x20000000000
    mov    x5, #-0x100000
    stp    x6, x5, [x19, #16]
    movz   x6, #0
    movk   x6, #0x0010, lsl 16
    movk   x6, #0x0200, lsl 32
    str    x6, [x19, #32]
    ldr    q0, [x2, #256]
    ldr    q1, [x2, #272]
.Linv25519_bigloop:

    umull x30, w7, w13
    lsr x2, x10, #32
    lsr x1, x11, #32
    umull x6, w9, w11
    umull x17, w7, w2
    umull x2, w9, w1
    lsr x1, x13, #32
    umull x19, w7, w10
    lsr x16, x7, #32
    umull x1, w7, w1
    lsr x3, x9, #32
    umaddl x16, w16, w10, x17
    umaddl x3, w3, w11, x2
    dup v2.2D, x11
    smulh x2, x9, x11
    dup v3.2D, x13
    add x17, x19, x16, lsl #32
    add x19, x6, x3, lsl #32
    lsr x3, x14, #32
    lsr x6, x7, #32
    adds x16, x17, x19
    umaddl x19, w6, w13, x1
    lsr x1, x15, #32
    smulh x6, x7, x10
    add x17, x30, x19, lsl #32
    lsr x19, x16, #60
    lsr x16, x12, #32
    umull x16, w9, w16
    smulh x30, x9, x12
    adc x2, x6, x2
    lsr x6, x9, #32
    lsl x2, x2, #4
    umaddl x6, w6, w12, x16
    umull x9, w9, w12
    lsr x16, x11, #32
    orr x2, x19, x2
    smulh x19, x7, x13
    lsr x7, x13, #32
    add x6, x9, x6, lsl #32
    lsr x9, x14, #32
    adds x6, x6, x17
    adc x30, x30, x19
    umull x17, w15, w16
    lsr x16, x6, #60
    umull x19, w14, w7
    lsl x6, x30, #4
    umull x30, w10, w9
    umull x9, w15, w11
    orr x16, x16, x6
    umaddl x6, w1, w11, x17
    umaddl x17, w3, w13, x19
    lsr x11, x15, #32
    umull x7, w14, w13
    lsr x19, x10, #32
    umull x13, w12, w11
    add x11, x9, x6, lsl #32
    umaddl x30, w19, w14, x30
    lsr x6, x12, #32
    umull x14, w10, w14
    umull x9, w12, w15
    umaddl x15, w6, w15, x13
    ldr q4, [sp, #112]
    add x14, x14, x30, lsl #32
    ldr q5, [sp, #128]
    add x13, x7, x17, lsl #32
    add x7, x9, x15, lsl #32
    add x14, x11, x14
    add x15, x13, x7
    add x7, x14, x2
    add x2, x16, x15
    bic x9, x7, x5
.Linv25519_loop20_init:

    dup    v6.2d, x10
    ldr    q10, [x0, #128]
    dup    v7.2d, x12
    bic    x3, x2, x5
    ldr    q11, [x0, #144]
    xtn    v9.2s, v4.2d
    xtn    v8.2s, v5.2d
    and    v14.16b, v2.16b, v10.16b
    ldr    q20, [x0, #0]
    and    v12.16b, v6.16b, v10.16b
    xtn    v16.2s, v12.2d
    xtn    v18.2s, v14.2d
    and    v13.16b, v7.16b, v11.16b
    ldr    q21, [x0, #16]
    smull  v16.2d, v16.2s, v9.2s
    xtn    v17.2s, v13.2d
    xtn    v20.2s, v20.2d
    and    v15.16b, v3.16b, v11.16b
    ldr    q30, [x0, #224]
    smull  v17.2d, v17.2s, v8.2s
    smlal  v16.2d, v18.2s, v8.2s
    ldr    x30, [sp, #496]
    xtn    v19.2s, v15.2d
    ldr    q18, [x0, #96]
    xtn    v21.2s, v21.2d
    xtn    v12.2s, v12.2d
    smlal  v17.2d, v19.2s, v9.2s
    ldr    x19, [sp, #512]
    ldr    q19, [x0, #112]
    xtn    v31.2s, v16.2d
    xtn    v18.2s, v18.2d
    xtn    v13.2s, v13.2d
    ushr   v6.2d, v6.2d, #30
    add    x3, x3, x30
    smull  v22.2d, v18.2s, v31.2s
    add    x9, x9, x19
    xtn    v31.2s, v17.2d
    xtn    v19.2s, v19.2d
    xtn    v6.2s, v6.2d
    xtn    v14.2s, v14.2d
    smull  v23.2d, v19.2s, v31.2s
    tst    x3, #1
    and    v22.16b, v10.16b, v22.16b
    ldr    q31, [x0, #240]
    xtn    v24.2s, v22.2d
    xtn    v15.2s, v15.2d
    ushr   v7.2d, v7.2d, #30
    csel   x13, x9, xzr, ne
    and    v23.16b, v11.16b, v23.16b
    ccmp   x4, #0, #8, ne
    smull  v24.2d, v24.2s, v20.2s
    csneg  x13, x13, x13, lt
    xtn    v25.2s, v23.2d
    xtn    v7.2s, v7.2d
    ushr   v2.2d, v2.2d, #30
    csneg  x4, x4, x4, lt
    smull  v25.2d, v25.2s, v21.2s
    csel   x9, x3, x9, ge
    sub    v16.2d, v16.2d, v24.2d
    csinc  x4, x4, x4, ge
    ldr    q24, [sp, #144]
    smull  v4.2d, v6.2s, v9.2s
    xtn    v2.2s, v2.2d
    add    x11, x3, x13
    sub    v17.2d, v17.2d, v25.2d
    tst    x11, #2
    ldr    q25, [sp, #160]
    xtn    v24.2s, v24.2d
    ushr   v3.2d, v3.2d, #30
    csel   x13, x9, xzr, ne
    smull  v28.2d, v24.2s, v12.2s
    asr    x3, x11, #1
    xtn    v25.2s, v25.2d
    xtn    v3.2s, v3.2d
    smull  v5.2d, v7.2s, v8.2s
    ccmp   x4, #0, #8, ne
    smull  v29.2d, v25.2s, v13.2s
    csneg  x13, x13, x13, lt
    smlal  v28.2d, v14.2s, v25.2s
    csneg  x4, x4, x4, lt
    smlal  v4.2d, v2.2s, v8.2s
    csel   x9, x3, x9, ge
    add    v16.2d, v16.2d, v30.2d
    csinc  x4, x4, x4, ge
    smlal  v29.2d, v15.2s, v24.2s
    add    x11, x3, x13
    smlal  v5.2d, v3.2s, v9.2s
    tst    x11, #2
    ushr   v16.2d, v16.2d, #30
    csel   x13, x9, xzr, ne
    add    v4.2d, v28.2d, v4.2d
    asr    x3, x11, #1
    add    v17.2d, v17.2d, v31.2d
    ccmp   x4, #0, #8, ne
    add    v4.2d, v16.2d, v4.2d
    csneg  x13, x13, x13, lt
    ushr   v17.2d, v17.2d, #30
    csneg  x4, x4, x4, lt
    add    v5.2d, v29.2d, v5.2d
    csel   x9, x3, x9, ge
    xtn    v31.2s, v4.2d
    csinc  x4, x4, x4, ge
    add    v5.2d, v17.2d, v5.2d
    add    x11, x3, x13
    smull  v8.2d, v31.2s, v18.2s
    tst    x11, #2
    xtn    v31.2s, v5.2d
    csel   x13, x9, xzr, ne
    asr    x3, x11, #1
    ccmp   x4, #0, #8, ne
    smull  v9.2d, v31.2s, v19.2s
    csneg  x13, x13, x13, lt
    and    v8.16b, v8.16b, v10.16b
    csneg  x4, x4, x4, lt
    xtn    v31.2s, v8.2d
    csel   x9, x3, x9, ge
    csinc  x4, x4, x4, ge
    add    x11, x3, x13
    and    v9.16b, v9.16b, v11.16b
    tst    x11, #2
    smull  v16.2d, v31.2s, v20.2s
    csel   x13, x9, xzr, ne
    xtn    v31.2s, v9.2d
    asr    x3, x11, #1
    smull  v20.2d, v6.2s, v24.2s
    ccmp   x4, #0, #8, ne
    smull  v17.2d, v31.2s, v21.2s
    csneg  x13, x13, x13, lt
    sub    v4.2d, v4.2d, v16.2d
    csneg  x4, x4, x4, lt
    ldr    q16, [sp, #176]
    smull  v21.2d, v7.2s, v25.2s
    smlal  v20.2d, v2.2s, v25.2s
    csel   x9, x3, x9, ge
    sub    v5.2d, v5.2d, v17.2d
    csinc  x4, x4, x4, ge
    ldr    q17, [sp, #192]
    xtn    v16.2s, v16.2d
    smlal  v21.2d, v3.2s, v24.2s
    add    x11, x3, x13
    smull  v24.2d, v12.2s, v16.2s
    tst    x11, #2
    xtn    v17.2s, v17.2d
    csel   x13, x9, xzr, ne
    smull  v19.2d, v3.2s, v16.2s
    asr    x3, x11, #1
    smull  v25.2d, v13.2s, v17.2s
    ccmp   x4, #0, #8, ne
    smlal  v24.2d, v14.2s, v17.2s
    csneg  x13, x13, x13, lt
    smull  v18.2d, v2.2s, v17.2s
    csneg  x4, x4, x4, lt
    smull  v17.2d, v7.2s, v17.2s
    csel   x9, x3, x9, ge
    smlal  v25.2d, v15.2s, v16.2s
    csinc  x4, x4, x4, ge
    add    v24.2d, v20.2d, v24.2d
    add    x11, x3, x13
    ldr    q20, [sp, #208]
    smull  v16.2d, v6.2s, v16.2s
    add    v17.2d, v19.2d, v17.2d
    tst    x11, #2
    add    v25.2d, v21.2d, v25.2d
    csel   x13, x9, xzr, ne
    ldr    q21, [sp, #224]
    xtn    v20.2s, v20.2d
    add    v16.2d, v18.2d, v16.2d
    asr    x3, x11, #1
    add    v4.2d, v0.2d, v4.2d
    ccmp   x4, #0, #8, ne
    xtn    v21.2s, v21.2d
    csneg  x13, x13, x13, lt
    add    v5.2d, v1.2d, v5.2d
    csneg  x4, x4, x4, lt
    smull  v18.2d, v12.2s, v20.2s
    csel   x9, x3, x9, ge
    smull  v19.2d, v13.2s, v21.2s
    csinc  x4, x4, x4, ge
    ushr   v4.2d, v4.2d, #30
    add    x11, x3, x13
    ushr   v5.2d, v5.2d, #30
    tst    x11, #2
    add    v24.2d, v4.2d, v24.2d
    csel   x13, x9, xzr, ne
    add    v25.2d, v5.2d, v25.2d
    asr    x3, x11, #1
    smlal  v18.2d, v14.2s, v21.2s
    ccmp   x4, #0, #8, ne
    smlal  v19.2d, v15.2s, v20.2s
    csneg  x13, x13, x13, lt
    add    v4.2d, v0.2d, v24.2d
    csneg  x4, x4, x4, lt
    add    v5.2d, v1.2d, v25.2d
    csel   x9, x3, x9, ge
    ushr   v4.2d, v4.2d, #30
    csinc  x4, x4, x4, ge
    ushr   v5.2d, v5.2d, #30
    add    x11, x3, x13
    add    v18.2d, v16.2d, v18.2d
    tst    x11, #2
    add    v19.2d, v17.2d, v19.2d
    csel   x13, x9, xzr, ne
    add    v18.2d, v4.2d, v18.2d
    asr    x3, x11, #1
    add    v19.2d, v5.2d, v19.2d
    ccmp   x4, #0, #8, ne
    add    v4.2d, v0.2d, v18.2d
    csneg  x13, x13, x13, lt
    add    v5.2d, v1.2d, v19.2d
    csneg  x4, x4, x4, lt
    and    v18.16b, v10.16b, v18.16b
    csel   x9, x3, x9, ge
    and    v19.16b, v11.16b, v19.16b
    str    q18, [sp, #144]
    shl    v16.2d, v18.2d, #30
    csinc  x4, x4, x4, ge
    shl    v17.2d, v19.2d, #30
    str    q19, [sp, #160]
    and    v24.16b, v10.16b, v24.16b
    add    x11, x3, x13
    and    v25.16b, v11.16b, v25.16b
    tst    x11, #2
    add    v16.2d, v16.2d, v24.2d
    csel   x13, x9, xzr, ne
    add    v17.2d, v17.2d, v25.2d
    asr    x3, x11, #1
    str    q16, [sp, #432]
    smull  v26.2d, v2.2s, v21.2s
    smull  v27.2d, v3.2s, v20.2s
    ccmp   x4, #0, #8, ne
    str    q17, [sp, #448]
    smull  v20.2d, v6.2s, v20.2s
    smull  v21.2d, v7.2s, v21.2s
    csneg  x13, x13, x13, lt
    ldr    q16, [sp, #240]
    ushr   v4.2d, v4.2d, #30
    ushr   v5.2d, v5.2d, #30
    csneg  x4, x4, x4, lt
    ldr    q17, [sp, #256]
    add    v20.2d, v20.2d, v26.2d
    xtn    v16.2s, v16.2d
    csel   x9, x3, x9, ge
    add    v21.2d, v21.2d, v27.2d
    csinc  x4, x4, x4, ge
    xtn    v17.2s, v17.2d
    add    x11, x3, x13
    smull  v26.2d, v12.2s, v16.2s
    tst    x11, #2
    smull  v27.2d, v13.2s, v17.2s
    csel   x13, x9, xzr, ne
    smull  v18.2d, v2.2s, v17.2s
    asr    x3, x11, #1
    smull  v19.2d, v3.2s, v16.2s
    ccmp   x4, #0, #8, ne
    smlal  v26.2d, v14.2s, v17.2s
    csneg  x13, x13, x13, lt
    smlal  v27.2d, v15.2s, v16.2s
    csneg  x4, x4, x4, lt
    smull  v16.2d, v6.2s, v16.2s
    csel   x9, x3, x9, ge
    smull  v17.2d, v7.2s, v17.2s
    csinc  x4, x4, x4, ge
    add    v26.2d, v26.2d, v20.2d
    add    x11, x3, x13
    add    v27.2d, v27.2d, v21.2d
    ldr    q20, [sp, #272]
    add    v16.2d, v16.2d, v18.2d
    tst    x11, #2
    ldr    q21, [sp, #288]
    add    v17.2d, v17.2d, v19.2d
    xtn    v20.2s, v20.2d
    csel   x13, x9, xzr, ne
    add    v26.2d, v4.2d, v26.2d
    asr    x3, x11, #1
    xtn    v21.2s, v21.2d
    ccmp   x4, #0, #8, ne
    smull  v18.2d, v12.2s, v20.2s
    csneg  x13, x13, x13, lt
    smull  v19.2d, v13.2s, v21.2s
    csneg  x4, x4, x4, lt
    add    v27.2d, v5.2d, v27.2d
    csel   x9, x3, x9, ge
    add    v4.2d, v26.2d, v0.2d
    csinc  x4, x4, x4, ge
    smlal  v18.2d, v14.2s, v21.2s
    add    x11, x3, x13
    smlal  v19.2d, v15.2s, v20.2s
    tst    x11, #2
    add    v5.2d, v27.2d, v1.2d
    csel   x13, x9, xzr, ne
    ushr   v4.2d, v4.2d, #30
    asr    x3, x11, #1
    ushr   v5.2d, v5.2d, #30
    ccmp   x4, #0, #8, ne
    add    v18.2d, v16.2d, v18.2d
    csneg  x13, x13, x13, lt
    add    v19.2d, v17.2d, v19.2d
    csneg  x4, x4, x4, lt
    add    v18.2d, v4.2d, v18.2d
    csel   x9, x3, x9, ge
    add    v19.2d, v5.2d, v19.2d
    csinc  x4, x4, x4, ge
    add    v4.2d, v0.2d, v18.2d
    add    x11, x3, x13
    add    v5.2d, v1.2d, v19.2d
    tst    x11, #2
    and    v18.16b, v10.16b, v18.16b
    csel   x13, x9, xzr, ne
    and    v19.16b, v11.16b, v19.16b
    str    q18, [sp, #208]
    shl    v16.2d, v18.2d, #30
    asr    x3, x11, #1
    shl    v17.2d, v19.2d, #30
    str    q19, [sp, #224]
    and    v26.16b, v10.16b, v26.16b
    ccmp   x4, #0, #8, ne
    and    v27.16b, v11.16b, v27.16b
    str    q26, [sp, #176]
    add    v16.2d, v16.2d, v26.2d
    csneg  x13, x13, x13, lt
    add    v17.2d, v17.2d, v27.2d
    str    q27, [sp, #192]
    smull  v28.2d, v2.2s, v21.2s
    csneg  x4, x4, x4, lt
    str    q16, [sp, #464]
    smull  v29.2d, v3.2s, v20.2s
    smull  v20.2d, v6.2s, v20.2s
    csel   x9, x3, x9, ge
    str    q17, [sp, #480]
    smull  v21.2d, v7.2s, v21.2s
    csinc  x4, x4, x4, ge
    add    x11, x3, x13
    ldr    q16, [sp, #304]
    tst    x11, #2
    add    v20.2d, v20.2d, v28.2d
    csel   x13, x9, xzr, ne
    ldr    q17, [sp, #320]
    add    v21.2d, v21.2d, v29.2d
    xtn    v16.2s, v16.2d
    asr    x3, x11, #1
    ldr    q18, [sp, #336]
    ccmp   x4, #0, #8, ne
    xtn    v17.2s, v17.2d
    csneg  x13, x13, x13, lt
    smull  v28.2d, v12.2s, v16.2s
    ldr    q19, [sp, #352]
    smull  v29.2d, v13.2s, v17.2s
    csneg  x4, x4, x4, lt
    smull  v26.2d, v2.2s, v17.2s
    csel   x9, x3, x9, ge
    smull  v27.2d, v3.2s, v16.2s
    csinc  x4, x4, x4, ge
    smlal  v28.2d, v14.2s, v17.2s
    add    x11, x3, x13
    smlal  v29.2d, v15.2s, v16.2s
    tst    x11, #2
    smull  v16.2d, v6.2s, v16.2s
    csel   x13, x9, xzr, ne
    smull  v17.2d, v7.2s, v17.2s
    asr    x3, x11, #1
    xtn    v18.2s, v18.2d
    xtn    v19.2s, v19.2d
    ushr   v4.2d, v4.2d, #30
    ccmp   x4, #0, #8, ne
    add    v16.2d, v26.2d, v16.2d
    csneg  x13, x13, x13, lt
    add    v17.2d, v27.2d, v17.2d
    csneg  x4, x4, x4, lt
    smull  v26.2d, v12.2s, v18.2s
    csel   x9, x3, x9, ge
    smull  v27.2d, v13.2s, v19.2s
    csinc  x4, x4, x4, ge
    ushr   v5.2d, v5.2d, #30
    add    x11, x3, x13
    add    v28.2d, v28.2d, v20.2d
    tst    x11, #2
    smlal  v26.2d, v14.2s, v19.2s
    csel   x13, x9, xzr, ne
    smlal  v27.2d, v15.2s, v18.2s
    asr    x3, x11, #1
    add    v29.2d, v29.2d, v21.2d
    ccmp   x4, #0, #8, ne
    add    v28.2d, v28.2d, v4.2d
    csneg  x13, x13, x13, lt
    add    v26.2d, v16.2d, v26.2d
    csneg  x4, x4, x4, lt
    add    v27.2d, v17.2d, v27.2d
    ldr    q16, [sp, #368]
    add    v29.2d, v29.2d, v5.2d
    csel   x9, x3, x9, ge
    ldr    q17, [sp, #384]
    add    v4.2d, v28.2d, v0.2d
    xtn    v16.2s, v16.2d
    csinc  x4, x4, x4, ge
    add    v5.2d, v29.2d, v1.2d
    add    x11, x3, x13
    xtn    v17.2s, v17.2d
    tst    x11, #2
    smull  v12.2d, v12.2s, v16.2s
    csel   x13, x9, xzr, ne
    smull  v13.2d, v13.2s, v17.2s
    asr    x3, x11, #1
    smull  v20.2d, v2.2s, v19.2s
    ccmp   x4, #0, #8, ne
    smull  v21.2d, v3.2s, v18.2s
    csneg  x13, x13, x13, lt
    ushr   v4.2d, v4.2d, #30
    csneg  x4, x4, x4, lt
    ushr   v5.2d, v5.2d, #30
    csel   x9, x3, x9, ge
    smull  v18.2d, v6.2s, v18.2s
    csinc  x4, x4, x4, ge
    smull  v19.2d, v7.2s, v19.2s
    add    x11, x3, x13
    add    v26.2d, v26.2d, v4.2d
    tst    x11, #2
    add    v27.2d, v27.2d, v5.2d
    csel   x13, x9, xzr, ne
    smlal  v12.2d, v17.2s, v14.2s
    asr    x3, x11, #1
    smlal  v13.2d, v16.2s, v15.2s
    ccmp   x4, #0, #8, ne
    add    v4.2d, v26.2d, v0.2d
    csneg  x13, x13, x13, lt
    add    v5.2d, v27.2d, v1.2d
    csneg  x4, x4, x4, lt
    add    v18.2d, v20.2d, v18.2d
    csel   x9, x3, x9, ge
    add    v19.2d, v21.2d, v19.2d
    csinc  x4, x4, x4, ge
    ushr   v4.2d, v4.2d, #30
    add    x11, x3, x13
    ushr   v5.2d, v5.2d, #30
    tst    x11, #2
    add    v12.2d, v12.2d, v18.2d
    csel   x13, x9, xzr, ne
    add    v13.2d, v13.2d, v19.2d
    asr    x3, x11, #1
    smull  v2.2d, v17.2s, v2.2s
    ccmp   x4, #0, #8, ne
    smull  v3.2d, v16.2s, v3.2s
    csneg  x13, x13, x13, lt
    shl    v22.2d, v22.2d, #15
    csneg  x4, x4, x4, lt
    shl    v23.2d, v23.2d, #15
    csel   x9, x3, x9, ge
    add    v12.2d, v12.2d, v4.2d
    csinc  x4, x4, x4, ge
    add    v13.2d, v13.2d, v5.2d
    add    x11, x3, x13
    add    v12.2d, v22.2d, v12.2d
    asr    x3, x11, #1
    add    v13.2d, v23.2d, v13.2d
    smlal  v2.2d, v16.2s, v6.2s
    smlal  v3.2d, v17.2s, v7.2s
    shl    v8.2d, v8.2d, #15
    shl    v9.2d, v9.2d, #15
    add    v4.2d, v0.2d, v12.2d
    add    v5.2d, v1.2d, v13.2d
    ushr   v4.2d, v4.2d, #30
    ushr   v5.2d, v5.2d, #30
    add    v8.2d, v2.2d, v8.2d
    add    v9.2d, v3.2d, v9.2d
    add    v8.2d, v4.2d, v8.2d
    add    v9.2d, v5.2d, v9.2d
    and    v28.16b, v28.16b, v10.16b
    and    v29.16b, v29.16b, v11.16b
    str    q28, [sp, #240]
    and    v26.16b, v10.16b, v26.16b
    and    v27.16b, v11.16b, v27.16b
    str    q29, [sp, #256]
    add    v2.2d, v8.2d, v0.2d
    add    v3.2d, v9.2d, v1.2d
    str    q26, [sp, #272]
    and    v12.16b, v10.16b, v12.16b
    and    v13.16b, v11.16b, v13.16b
    str    q27, [sp, #288]
    ushr   v2.2d, v2.2d, #30
    str    q12, [sp, #304]
    ushr   v3.2d, v3.2d, #30
    str    q13, [sp, #320]
    ldr    q4, [x0, #64]
    ldr    q5, [x0, #80]
.Linv25519_extract_init:

    ldr x17, [sp, #528]
    add v31.2D, v2.2D, v0.2D
    ldr q6, [x0, #192]
    mov x15, x2
    lsr x1, x2, #32
    lsr x14, x15, #32
    add x6, x3, x17
    ldr q7, [x0, #208]
    asr x11, x6, #42
    add x17, x9, x17
    add v12.2D, v3.2D, v1.2D
    asr x10, x17, #42
    ushr v31.2D, v31.2D, #15
    add x17, x11, #2097152
    ushr v28.2D, v12.2D, #15
    umull x6, w1, w17
    umull x17, w2, w17
    sub v12.2D, v31.2D, v6.2D
    sub v13.2D, v28.2D, v7.2D
    add x1, x10, #2097152
    umull x13, w14, w1
    ldr q31, [x0, #160]
    umull x12, w15, w1
    mov x14, x7
    add x1, x17, x6, lsl #32
    ldr q28, [x0, #176]
    lsr x16, x14, #32
    lsr x19, x7, #32
    sub x2, x1, x2, lsl   #21
    sub v2.2D, v2.2D, v31.2D
    add x6, x12, x13, lsl #32
    sub v31.2D, v3.2D, v28.2D
    ldr x13, [sp, #504]
    and v8.16B, v8.16B, v10.16B
    sub x12, x6, x15, lsl   #21
    and v9.16B, v9.16B, v11.16B
    and v2.16B, v2.16B, v4.16B
    str x10, [sp, #416]
    add x17, x3, x13
    and v3.16B, v31.16B, v5.16B
    lsl x17, x17, #22
    ldr q28, [x0, #32]
    add x15, x9, x13
    mov x9, #2
    asr x3, x17, #43
    xtn v31.2S, v12.2D
    xtn v4.2S, v28.2D
    lsl x17, x15, #22
    add x15, x3, #1048576
    ldr q29, [x0, #48]
    umull x16, w16, w15
    asr x17, x17, #43
    umull x15, w14, w15
    smull v4.2D, v31.2S, v4.2S
    str x17, [sp, #400]
    add x17, x17, #1048576
    xtn v30.2S, v13.2D
    umull x19, w19, w17
    xtn v31.2S, v29.2D
    umull x17, w7, w17
    add x15, x15, x16, lsl #32
    add v24.2D, v24.2D, v4.2D
    smlal v25.2D, v30.2S, v31.2S
    str x11, [sp, #408]
    sub x14, x15, x14, lsl   #20
    str q8, [sp, #336]
    add x17, x17, x19, lsl #32
    str q9, [sp, #352]
    add x2, x14, x2
    str q2, [sp, #368]
    sub x7, x17, x7, lsl   #20
    str q3, [sp, #384]
    str q24, [sp, #112]
    asr x2, x2, #20
    add x7, x12, x7
    str q25, [sp, #128]
    asr x7, x7, #20
    str x3, [sp, #424]
.Linv25519_loop20:

    ldr    x30, [sp, #496]
    bic    x10, x2, x5
    ldr    x19, [sp, #512]
    bic    x3, x7, x5
    mov    x11, #2
    add    x10, x10, x30
    add    x3, x3, x19
    tst    x10, #1
.Linv25519_loop2:

    csel   x13, x3, xzr, ne
    sub    x11, x11, #1
    ccmp   x4, #0, #8, ne
    csneg  x13, x13, x13, lt
    csneg  x4, x4, x4, lt
    csel   x3, x10, x3, ge
    csinc  x4, x4, x4, ge
    add    x15, x10, x13
    tst    x15, #2
    asr    x10, x15, #1
    csel   x13, x3, xzr, ne
    ccmp   x4, #0, #8, ne
    csneg  x13, x13, x13, lt
    csneg  x4, x4, x4, lt
    csel   x3, x10, x3, ge
    csinc  x4, x4, x4, ge
    add    x15, x10, x13
    tst    x15, #2
    asr    x10, x15, #1
    csel   x13, x3, xzr, ne
    ccmp   x4, #0, #8, ne
    csneg  x13, x13, x13, lt
    csneg  x4, x4, x4, lt
    csel   x3, x10, x3, ge
    csinc  x4, x4, x4, ge
    add    x15, x10, x13
    tst    x15, #2
    asr    x10, x15, #1
    csel   x13, x3, xzr, ne
    ccmp   x4, #0, #8, ne
    csneg  x13, x13, x13, lt
    csneg  x4, x4, x4, lt
    csel   x3, x10, x3, ge
    csinc  x4, x4, x4, ge
    add    x15, x10, x13
    tst    x15, #2
    asr    x10, x15, #1
    csel   x13, x3, xzr, ne
    ccmp   x4, #0, #8, ne
    csneg  x13, x13, x13, lt
    csneg  x4, x4, x4, lt
    csel   x3, x10, x3, ge
    csinc  x4, x4, x4, ge
    add    x15, x10, x13
    tst    x15, #2
    asr    x10, x15, #1
    csel   x13, x3, xzr, ne
    ccmp   x4, #0, #8, ne
    csneg  x13, x13, x13, lt
    csneg  x4, x4, x4, lt
    csel   x3, x10, x3, ge
    csinc  x4, x4, x4, ge
    add    x15, x10, x13
    tst    x15, #2
    asr    x10, x15, #1
    csel   x13, x3, xzr, ne
    ccmp   x4, #0, #8, ne
    csneg  x13, x13, x13, lt
    csneg  x4, x4, x4, lt
    csel   x3, x10, x3, ge
    csinc  x4, x4, x4, ge
    add    x15, x10, x13
    tst    x15, #2
    asr    x10, x15, #1
    csel   x13, x3, xzr, ne
    ccmp   x4, #0, #8, ne
    csneg  x13, x13, x13, lt
    csneg  x4, x4, x4, lt
    csel   x3, x10, x3, ge
    csinc  x4, x4, x4, ge
    add    x15, x10, x13
    tst    x15, #2
    asr    x10, x15, #1
    csel   x13, x3, xzr, ne
    ccmp   x4, #0, #8, ne
    csneg  x13, x13, x13, lt
    csneg  x4, x4, x4, lt
    csel   x3, x10, x3, ge
    csinc  x4, x4, x4, ge
    add    x15, x10, x13
    tst    x15, #2
    asr    x10, x15, #1
    csel   x13, x3, xzr, ne
    ccmp   x4, #0, #8, ne
    csneg  x13, x13, x13, lt
    csneg  x4, x4, x4, lt
    csel   x3, x10, x3, ge
    csinc  x4, x4, x4, ge
    add    x15, x10, x13
    asr    x10, x15, #1
    tst    x15, #2
    cbnz   x11, .Linv25519_loop2

    subs    x9, x9, #1
    beq    .Linv25519_lastloop

.Linv25519_extract:

    ldr    x11, [sp, #528]
    mov    x13, x2
    lsr    x14, x13, #32
    lsr    x30, x2, #32
    mov    x15, x7
    lsr    x19, x7, #32
    add    x12, x10, x11
    add    x11, x3, x11
    asr    x12, x12, #42
    asr    x11, x11, #42
    add    x1, x12, #2097152
    add    x6, x11, #2097152
    umull  x30, w30, w1
    umull  x14, w14, w6
    umull  x6, w13, w6
    umull  x1, w2, w1
    add    x6, x6, x14, lsl #32
    ldr    x14, [sp, #504]
    add    x1, x1, x30, lsl #32
    sub    x13, x6, x13, lsl #21
    ldr    x30, [sp, #400]
    sub    x2, x1, x2, lsl #21
    add    x3, x3, x14
    add    x10, x10, x14
    lsl    x3, x3, #22
    lsl    x10, x10, #22
    lsr    x1, x15, #32
    ldr    x14, [sp, #424]
    asr    x3, x3, #43
    asr    x10, x10, #43
    add    x17, x3, #1048576
    add    x16, x10, #1048576
    umull  x19, w19, w17
    umull  x1, w1, w16
    umull  x17, w7, w17
    umull  x16, w15, w16
    smull  x14, w11, w14
    add    x17, x17, x19, lsl #32
    add    x16, x16, x1, lsl #32
    sub    x7, x17, x7, lsl #20
    sub    x15, x16, x15, lsl #20
    add    x7, x13, x7
    ldr    x16, [sp, #408]
    add    x2, x15, x2
    ldr    x13, [sp, #400]
    ldr    x15, [sp, #416]
    asr    x7, x7, #20
    smull  x11, w16, w11
    asr    x2, x2, #20
    smull  x13, w3, w13
    smull  x3, w15, w3
    smull  x15, w10, w15
    smull  x10, w30, w10
    ldr    x30, [sp, #424]
    smull  x16, w12, w16
    add    x11, x3, x11
    add    x3, x13, x14
    smull  x12, w30, w12
    add    x10, x12, x10
    add    x12, x15, x16
.Linv25519_first_loop:

    str    x11, [sp, #416]
    str    x3, [sp, #400]
    str    x12, [sp, #408]
    str    x10, [sp, #424]
    b .Linv25519_loop20

.Linv25519_lastloop:

    ldr x6, [sp, #528]
    ldr x12, [sp, #424]
    ldr x9, [sp, #408]
    add x1, x10, x6
    add x13, x3, x6
    asr x15, x1, #42
    asr x11, x13, #42
    lsr x13, x12, #32
    lsr x6, x9, #32
    add x2, x11, #2097152
    add x16, x11, #2097152
    umull x11, w13, w2
    add x13, x15, #2097152
    umull x1, w12, w2
    lsr x17, x9, #32
    umull x6, w6, w16
    ldr x2, [sp, #504]
    umull x30, w9, w16
    ldr x14, [sp, #400]
    umull x19, w17, w13
    ldr x7, [sp, #416]
    add x1, x1, x11, lsl #32
    umull x13, w9, w13
    add x11, x10, x2
    add x3, x3, x2
    sub x10, x1, x12, lsl #21
    add x6, x30, x6, lsl #32
    lsl x12, x11, #22
    lsl x16, x3, #22
    sub x11, x6, x9, lsl #21
    add x3, x13, x19, lsl #32
    asr x13, x12, #43
    asr x1, x16, #43
    sub x9, x3, x9, lsl #21
    lsr x17, x14, #32
    add x12, x1, #1048576
    add x1, x1, #1048576
    umull x3, w17, w12
    lsr x6, x7, #32
    umull x2, w14, w12
    add x16, x13, #1048576
    umull x19, w6, w1
    umull x17, w7, w1
    ldr x12, [sp, #424]
    umull x6, w6, w16
    add x1, x15, #2097152
    add x3, x2, x3, lsl #32
    ldr x30, [sp, #400]
    umull x15, w7, w16
    lsr x16, x12, #32
    umull x2, w12, w1
    add x13, x13, #1048576
    umull x1, w16, w1
    lsr x16, x30, #32
    sub x3, x3, x14, lsl #20
    umull x14, w30, w13
    add x17, x17, x19, lsl #32
    umull x16, w16, w13
    add x6, x15, x6, lsl #32
    add x10, x3, x10
    sub x3, x17, x7, lsl #20
    add x1, x2, x1, lsl #32
    sub x13, x6, x7, lsl #20
    ldr x7, [sp, #432]
    sub x2, x1, x12, lsl #21
    add x14, x14, x16, lsl #32
    add x11, x3, x11
    add x12, x13, x9
    sub x15, x14, x30, lsl #20
    ldr x9, [sp, #448]
    ldr x14, [sp, #464]
    add x13, x2, x15
    ldr x15, [sp, #480]
    subs    x8, x8, #1
    bne     .Linv25519_bigloop

    lsl    x14, x14, #60
    lsl    x15, x15, #60
    lsr    x0, x10, #32
    lsr    x3, x11, #32
    add    x7, x14, x7
    add    x9, x15, x9
    lsr    x2, x7, #32
    lsr    x4, x9, #32
    lsr    x5, x10, #32
    lsr    x8, x11, #32
    umull  x2, w10, w2
    umull  x4, w11, w4
    umaddl x2, w0, w7, x2
    umaddl x4, w3, w9, x4
    umull  x7, w10, w7
    umull  x9, w11, w9
    add    x7, x7, x2, lsl #32
    add    x9, x9, x4, lsl #32
    add    x7, x7, x9
    asr    x7, x7, #60
    add    x1, x7, #8
    add    x6, x7, #8
    umull  x5, w5, w1
    umull  x8, w8, w6
    umull  x1, w10, w1
    umull  x6, w11, w6
    add    x1, x1, x5, lsl #32
    add    x6, x6, x8, lsl #32
    sub    x10, x1, x10, lsl #3
    sub    x11, x6, x11, lsl #3
.Linv25519_cneg:

    lsr x12, x11, #32
    ldr x5, [sp, #376]
    ldr x4, [sp, #360]
    lsr x2, x11, #32
    lsr x8, x10, #32
    ldr x0, [sp, #392]
    ldr x9, [sp, #328]
    umull x19, w5, w10
    lsl x14, x4, #30
    umull x3, w5, w8
    umull x13, w0, w2
    lsr x30, x5, #32
    add x6, x14, x9
    umull x4, w0, w11
    umull x1, w6, w12
    lsr x12, x10, #32
    smulh x2, x5, x10
    lsr x14, x6, #32
    lsr x7, x0, #32
    ldr x9, [sp, #312]
    ldr x8, [sp, #280]
    umaddl x30, w30, w10, x3
    ldr x3, [sp, #344]
    umaddl x13, w7, w11, x13
    smulh x5, x6, x11
    lsl x7, x3, #30
    add x3, x19, x30, lsl #32
    add x4, x4, x13, lsl  #32
    add x30, x7, x9
    lsr x13, x30, #32
    ldr x7, [sp, #248]
    umull x19, w30, w12
    umull x12, w6, w11
    umaddl x1, w14, w11, x1
    umull x14, w30, w10
    lsr x9, x10, #32
    umaddl x19, w13, w10, x19
    smulh x6, x30, x10
    add x13, x12, x1, lsl #32
    add x19, x14, x19, lsl #32
    ldr x12, [sp, #264]
    adds x13, x19, x13
    ldr x14, [sp, #296]
    smulh x1, x0, x11
    adc x5, x6, x5
    lsl x30, x5, #52
    lsl x19, x8, #30
    adds x0, x3, x4
    lsl x8, x14, #30
    lsr x14, x11, #32
    lsr x4, x13, #12
    add x12, x8, x12
    add x6, x19, x7
    orr x8, x4, x30
    lsr x3, x6, #32
    adc x30, x2, x1
    umull x7, w6, w9
    ldr x4, [sp, #232]
    umull x1, w12, w14
    mov x9, x0
    umull x2, w12, w11
    lsr x14, x12, #32
    umull x19, w6, w10
    umaddl x7, w3, w10, x7
    ldr x3, [sp, #216]
    lsr x9, x9, #16
    umaddl x1, w14, w11, x1
    lsl x14, x0, #48
    smulh x12, x12, x11
    lsl x0, x4, #30
    lsl x4, x3, #30
    ldr x3, [sp, #184]
    lsl x30, x30, #48
    add x1, x2, x1, lsl #32
    asr x2, x5, #12
    add x19, x19, x7, lsl #32
    lsr x5, x10, #32
    mov x7, x13
    add x3, x4, x3
    umull x5, w3, w5
    ldr x13, [sp, #200]
    orr x30, x30, x9
    smulh x4, x6, x10
    lsl x9, x7, #52
    adds x14, x8, x14
    adc x2, x2, x30
    lsr x8, x3, #32
    add x6, x0, x13
    lsr x7, x11, #32
    lsr x30, x6, #32
    adds x1, x19, x1
    adc x12, x4, x12
    umull x0, w6, w7
    mov x19, x12
    umull x13, w6, w11
    lsr x4, x1, #8
    umull x7, w3, w10
    umaddl x5, w8, w10, x5
    lsl x8, x12, #56
    umaddl x30, w30, w11, x0
    asr x0, x19, #63
    asr x19, x12, #8
    smulh x12, x3, x10
    orr x3, x4, x8
    add x4, x7, x5, lsl #32
    adds x9, x9, x3
    add x8, x13, x30, lsl #32
    adcs x3, x14, x19
    lsr x5, x10, #32
    adc x14, x0, x2
    ldr x0, [sp, #152]
    adds x4, x4, x8
    mov x13, x4
    smulh x8, x6, x11
    mov x19, x1
    ldr x7, [sp, #120]
    lsl x1, x0, #30
    add x30, x7, x1
    lsl x1, x19, #56
    lsr x19, x30, #32
    adc x6, x12, x8
    umull x8, w30, w5
    mov x0, x6
    umull x2, w30, w10
    lsl x12, x0, #60
    lsr x5, x4, #4
    ldr x7, [sp, #136]
    asr x4, x6, #4
    ldr x0, [sp, #168]
    umaddl x8, w19, w10, x8
    orr x12, x5, x12
    smulh x5, x30, x10
    lsl x0, x0, #30
    add x30, x2, x8, lsl #32
    add x2, x7, x0
    lsr x0, x11, #32
    adds x19, x12, x1
    umull x8, w2, w0
    mov x1, x6
    adcs x4, x4, x9
    asr x9, x1, #63
    lsr x10, x2, #32
    adcs x6, x9, x3
    umull x0, w2, w11
    adc x7, x9, x14
    umaddl x14, w10, w11, x8
    smulh x9, x2, x11
    add x0, x0, x14, lsl #32
    adds x8, x30, x0
    adc x3, x5, x9
    lsl x9, x13, #60
    mov x0, x3
    asr x0, x0, #63
    adds x1, x8, x9
    adcs x12, x3, x19
    adcs x9, x0, x4
    adcs x19, x0, x6
    adcs x3, x0, x7
    adds x0, x19, x19
    adc x2, x3, x3
    lsr x0, x2, #32
    umull x3, w28, w0
    lsr x0, x28, #32
    umull x8, w28, w2
    umaddl x0, w0, w2, x3
    smulh x3, x28, x2
    add x0, x8, x0, lsl #32
    mov x8, x2
    adds x1, x0, x1
    asr x8, x8, #63
    adcs x12, x3, x12
    adcs x9, x8, x9
    bic x0, x19, #0x8000000000000000
    adcs x0, x8, x0
    eor x3, x2, x2
    adcs x7, x8, x3
    adds x2, x0, x0
    adc x7, x7, x7
    lsr x6, x7, #32
    bic x4, x0, #0x8000000000000000
    umull x30, w28, w6
    umull x13, w28, w7
    lsr x6, x28, #32
    umaddl x2, w6, w7, x30
    smulh x30, x28, x7
    add x19, x13, x2, lsl #32
    adds x1, x19, x1
    adcs x3, x30, x12
    mov x7, x1
    mov x0, x3
    mov x13, x9
    mov x1, x4
    adds x3, x28, x7
    adcs x9, x0, xzr
    adcs x2, x13, xzr
    adcs x7, x1, xzr
    bic x4, x7, #0x8000000000000000
    mov x13, x7
    asr x12, x13, #63
    and x7, x12, x28
    adds x13, x7, x3
    adcs x12, x9, xzr
    adcs x9, x2, xzr
    ldr x0, [sp, #536]
    subs x1, x13, x28
    sbcs x2, x12, xzr
    stp x1, x2, [x0, #0]
    sbcs x3, x9, xzr
    sbc x4, x4, xzr
    stp x3, x4, [x0, #16]
    ldp    x29, x30, [sp, #80]
    ldp    x19, x28, [sp, #64]
    ldp    d14, d15, [sp, #48]
    ldp    d12, d13, [sp, #32]
    ldp    d10, d11, [sp, #16]
    ldp    d8, d9, [sp, #0]

    // wipe the frame
    mov    x0, sp
    add    x1, sp, #544
.Linv25519_wipe:
    stp    xzr, xzr, [x0], #32
    stp    xzr, xzr, [x0, #-16]
    cmp    x0, x1
    b.ne    .Linv25519_wipe
    add    sp, sp, #544
    ret
