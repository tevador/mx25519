/* Copyright (c) 2022 tevador <tevador@gmail.com>
 *
 * This file is part of mx25519, which is released under LGPLv3.
 * See LICENSE for full license details.
*/

#ifndef DIGIT_OPS_H
#define DIGIT_OPS_H

#include "digit.h"
#include "platform.h"

#include <stdbool.h>

typedef uint8_t carry;

#define digit_load platform_load64
#define digit_store platform_store64

/* Returns x == 0 in constant time. */
static FORCE_INLINE bool digit_eq_zero(digit x) {
    return 1 ^ ((x | -x) >> (DIGIT_RADIX - 1));
}

/* Returns x < y in constant time. */
static FORCE_INLINE bool digit_lt(digit x, digit y) {
    return (x ^ ((x ^ y) | ((x - y) ^ y))) >> (DIGIT_RADIX - 1);
}

/* Digit multiplication. Returns the low half of the result. The
   high half is stored in *hi */
static digit digit_mul(
    digit a, digit b, digit* hi);

/* Digit addition with carry. The result is stored in *sum_out. Returns
   the carry. */
static carry digit_addc(
    carry carry_in,
    digit addend1, digit addend2,
    digit* sum_out);

/* Digit subtraction with borrow. The result is stored in *diff_out. Returns
   the carry. */
static carry digit_subb(
    carry borrow_in,
    digit minuend, digit subtrahend,
    digit* diff_out);

/* Shifts a 2-digit quantity to the right by a number of bits specified
   by shift and returns the low digit of the result */
static digit digit_shr(
    digit high_in, digit low_in, uint8_t shift);

/* Shifts a 2-digit quantity to the left by a number of bits specified
   by shift and returns the high digit of the result. */
static digit digit_shl(
    digit high_in, digit low_in, uint8_t shift);

#if defined(PLATFORM_X64_INTRIN)

#include <intrin.h>
#include <inttypes.h>

static FORCE_INLINE digit digit_mul(digit a, digit b, digit* hi) {
    return _umul128(a, b, hi);
}

static FORCE_INLINE carry digit_addc(
    carry carry_in, digit addend1, digit addend2, digit* sum_out) {
    return _addcarry_u64(carry_in, addend1, addend2, sum_out);
}

static FORCE_INLINE carry digit_subb(
    carry borrow_in, digit minuend, digit subtrahend, digit* diff_out) {
    return _subborrow_u64(borrow_in, minuend, subtrahend, diff_out);
}

static FORCE_INLINE digit digit_shr(
    digit high_in, digit low_in, uint8_t shift) {
    return __shiftright128(low_in, high_in, shift);
}

static FORCE_INLINE digit digit_shl(
    digit high_in, digit low_in, uint8_t shift) {
    return __shiftleft128(low_in, high_in, shift);
}

#elif defined(PLATFORM_UINT128)

static FORCE_INLINE digit digit_mul(digit a, digit b, digit* hi) {
    uint128_t res = (uint128_t)a * (uint128_t)b;
    *hi = res >> DIGIT_RADIX;
    return (digit)res;
}

static FORCE_INLINE carry digit_addc(
    carry carry_in, digit addend1, digit addend2, digit* sum_out) {
    uint128_t temp = (uint128_t)addend1 + (uint128_t)addend2 + carry_in;
    *sum_out = (digit)temp;
    return (carry)(temp >> DIGIT_RADIX);
}

static FORCE_INLINE carry digit_subb(
    carry borrow_in, digit minuend, digit subtrahend, digit* diff_out) {
    uint128_t temp = (uint128_t)minuend - (uint128_t)subtrahend - borrow_in;
    *diff_out = (digit)temp;
    return (carry)(temp >> (sizeof(uint128_t) * 8 - 1));
}

static FORCE_INLINE digit digit_shr(
    digit high_in, digit low_in, uint8_t shift) {
    return (low_in >> shift) | (high_in << (DIGIT_RADIX - shift));
}

static FORCE_INLINE digit digit_shl(
    digit high_in, digit low_in, uint8_t shift) {
    return (high_in << shift) | (low_in >> (DIGIT_RADIX - shift));
}

#else

#define DIGIT_HBIT (DIGIT_RADIX/2)
#define MASK_LOW ((digit)(-1) >> DIGIT_HBIT)
#define MASK_HIGH ((digit)(-1) << DIGIT_HBIT)

static FORCE_INLINE digit digit_mul(digit a, digit b, digit* hi) {
    digit al, ah, bl, bh;
    digit albl, albh, ahbl, ahbh;
    digit tmp1, tmp2, tmp3, tmp4, carry;

    al = a & MASK_LOW;
    ah = a >> DIGIT_HBIT;
    bl = b & MASK_LOW;
    bh = b >> DIGIT_HBIT;

    albl = al * bl;
    albh = al * bh;
    ahbl = ah * bl;
    ahbh = ah * bh;
    digit lo = albl & MASK_LOW;

    tmp1 = albl >> DIGIT_HBIT;
    tmp2 = ahbl & MASK_LOW;
    tmp3 = albh & MASK_LOW;
    tmp4 = tmp1 + tmp2 + tmp3;
    carry = tmp4 >> DIGIT_HBIT;
    lo |= tmp4 << DIGIT_HBIT;

    tmp1 = ahbl >> DIGIT_HBIT;
    tmp2 = albh >> DIGIT_HBIT;
    tmp3 = ahbh & MASK_LOW;
    tmp4 = tmp1 + tmp2 + tmp3 + carry;
    *hi = tmp4 & MASK_LOW;
    carry = tmp4 & MASK_HIGH;
    *hi |= (ahbh & MASK_HIGH) + carry;

    return lo;
}

static FORCE_INLINE carry digit_addc(
    carry carry_in, digit addend1, digit addend2, digit* sum_out) {
    digit temp = addend1 + (digit)carry_in;
    *sum_out = addend2 + temp;
    return digit_lt(temp, (digit)carry_in)
        | digit_lt(*sum_out, temp);
}

static FORCE_INLINE carry digit_subb(
    carry borrow_in, digit minuend, digit subtrahend, digit* diff_out) {
    digit temp = minuend - subtrahend;
    *diff_out = temp - (digit)borrow_in;
    return digit_lt(minuend, subtrahend)
        | (borrow_in & digit_eq_zero(temp));
}

static FORCE_INLINE digit digit_shr(
    digit high_in, digit low_in, uint8_t shift) {
    return (low_in >> shift) | (high_in << (DIGIT_RADIX - shift));
}

static FORCE_INLINE digit digit_shl(
    digit high_in, digit low_in, uint8_t shift) {
    return (high_in << shift) | (low_in >> (DIGIT_RADIX - shift));
}

#endif

#endif
