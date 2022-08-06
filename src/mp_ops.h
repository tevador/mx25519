/* Copyright (c) 2022 tevador <tevador@gmail.com>
 *
 * This file is part of mx25519, which is released under LGPLv3.
 * See LICENSE for full license details.
*/

#ifndef MP_OPS_H
#define MP_OPS_H

#include "digit_ops.h"

#include <string.h>

/* 256x256->512 multiplication */
static void mp_mul256(
    digit c[8], const digit a[4], const digit b[4]);

/* 256x256->512 squaring */
static void mp_sqr256(
    digit c[8], const digit a[4]);

/* 256x256->256 multiplication */
static void mp_mul256_mod256(
    digit c[4], const digit a[4], const digit b[4]);

/* 512-bit addition, returns the carry */
static carry mp_add512(
    digit c[8], const digit a[8], const digit b[8]);

/* 256-bit addition, returns the carry */
static carry mp_add256(
    digit c[4], const digit a[4], const digit b[4]);

/* 256-bit subtraction c = a - b, returns the borrow */
static carry mp_sub256(
    digit c[4], const digit a[4], const digit b[4]);

/* 256-bit left-shift */
static void mp_shl(digit a[4], uint8_t count);

/* ======================================================================= */

static void mp_mul256(
    digit c[8], const digit a[4], const digit b[4])
{
    /*
                                 b3   b2   b1   b0
                                 a3   a2   a1   a0
          ----------------------------------------
                                         t001 t000
                                    t011 t010
                               t021 t020
                          t031 t030
                                    t101 t100
                               t111 t110
                          t121 t120
                     t131 t130
                               t201 t200
                          t211 t210
                     t221 t220
                t231 t230
                          t301 t300
                     t311 t310
                t321 t320
           t331 t330
          ----------------------------------------
             c7   c6   c5   c4   c3   c2   c1   c0
    */

    digit cr = 0;

    //c0 = t000
    digit t000, t001;
    t000 = digit_mul(a[0], b[0], &t001);
    c[0] = t000;

    //c1 = t001 + t010 + t100
    c[1] = t001;
    digit t010, t011;
    t010 = digit_mul(a[0], b[1], &t011);
    digit t100, t101;
    t100 = digit_mul(a[1], b[0], &t101);
    cr += digit_addc(0, c[1], t010, &c[1]);
    cr += digit_addc(0, c[1], t100, &c[1]);

    //c2 = t011 + t020 + t101 + t110 + t200
    cr = digit_addc(0, cr, t011, &c[2]);
    digit t020, t021;
    t020 = digit_mul(a[0], b[2], &t021);
    digit t110, t111;
    t110 = digit_mul(a[1], b[1], &t111);
    digit t201, t200;
    t200 = digit_mul(a[2], b[0], &t201);
    cr += digit_addc(0, c[2], t101, &c[2]);
    cr += digit_addc(0, c[2], t020, &c[2]);
    cr += digit_addc(0, c[2], t110, &c[2]);
    cr += digit_addc(0, c[2], t200, &c[2]);

    //c3 = t021 + t030 + t111 + t120 + t201 + t210 + t300
    cr = digit_addc(0, cr, t021, &c[3]);
    digit t030, t031;
    t030 = digit_mul(a[0], b[3], &t031);
    digit t120, t121;
    t120 = digit_mul(a[1], b[2], &t121);
    digit t210, t211;
    t210 = digit_mul(a[2], b[1], &t211);
    digit t300, t301;
    t300 = digit_mul(a[3], b[0], &t301);
    cr += digit_addc(0, c[3], t111, &c[3]);
    cr += digit_addc(0, c[3], t030, &c[3]);
    cr += digit_addc(0, c[3], t201, &c[3]);
    cr += digit_addc(0, c[3], t120, &c[3]);
    cr += digit_addc(0, c[3], t210, &c[3]);
    cr += digit_addc(0, c[3], t300, &c[3]);

    //c4 = t031 + t121 + t130 + t211 + t220 + t301 + t310
    cr = digit_addc(0, cr, t031, &c[4]);
    digit t130, t131;
    t130 = digit_mul(a[1], b[3], &t131);
    digit t220, t221;
    t220 = digit_mul(a[2], b[2], &t221);
    digit t310, t311;
    t310 = digit_mul(a[3], b[1], &t311);
    cr += digit_addc(0, c[4], t121, &c[4]);
    cr += digit_addc(0, c[4], t211, &c[4]);
    cr += digit_addc(0, c[4], t301, &c[4]);
    cr += digit_addc(0, c[4], t130, &c[4]);
    cr += digit_addc(0, c[4], t220, &c[4]);
    cr += digit_addc(0, c[4], t310, &c[4]);

    //c5 = t131 + t221 + t230 + t311 + t320
    cr = digit_addc(0, cr, t131, &c[5]);
    digit t230, t231;
    t230 = digit_mul(a[2], b[3], &t231);
    digit t320, t321;
    t320 = digit_mul(a[3], b[2], &t321);
    cr += digit_addc(0, c[5], t221, &c[5]);
    cr += digit_addc(0, c[5], t311, &c[5]);
    cr += digit_addc(0, c[5], t230, &c[5]);
    cr += digit_addc(0, c[5], t320, &c[5]);

    //c6 = t231 + t321 + t330
    cr = digit_addc(0, cr, t231, &c[6]);
    digit t330, t331;
    t330 = digit_mul(a[3], b[3], &t331);
    cr += digit_addc(0, c[6], t321, &c[6]);
    cr += digit_addc(0, c[6], t330, &c[6]);

    //c7 = t331
    c[7] = t331 + cr;
}

static void mp_sqr256(
    digit c[8], const digit a[4])
{
    digit cr = 0;

    //c0 = t000
    digit t000, t001;
    t000 = digit_mul(a[0], a[0], &t001);
    c[0] = t000;

    //c1 = t001 + t010 + t100
    c[1] = t001;
    digit t010, t011;
    t010 = digit_mul(a[0], a[1], &t011);
    cr += digit_addc(0, c[1], t010, &c[1]);
    cr += digit_addc(0, c[1], t010, &c[1]);

    //c2 = t011 + t020 + t101 + t110 + t200
    cr = digit_addc(0, cr, t011, &c[2]);
    digit t020, t021;
    t020 = digit_mul(a[0], a[2], &t021);
    digit t110, t111;
    t110 = digit_mul(a[1], a[1], &t111);
    cr += digit_addc(0, c[2], t011, &c[2]);
    cr += digit_addc(0, c[2], t020, &c[2]);
    cr += digit_addc(0, c[2], t110, &c[2]);
    cr += digit_addc(0, c[2], t020, &c[2]);

    //c3 = t021 + t030 + t111 + t120 + t201 + t210 + t300
    cr = digit_addc(0, cr, t021, &c[3]);
    digit t030, t031;
    t030 = digit_mul(a[0], a[3], &t031);
    digit t120, t121;
    t120 = digit_mul(a[1], a[2], &t121);
    cr += digit_addc(0, c[3], t111, &c[3]);
    cr += digit_addc(0, c[3], t030, &c[3]);
    cr += digit_addc(0, c[3], t021, &c[3]);
    cr += digit_addc(0, c[3], t120, &c[3]);
    cr += digit_addc(0, c[3], t120, &c[3]);
    cr += digit_addc(0, c[3], t030, &c[3]);

    //c4 = t031 + t121 + t130 + t211 + t220 + t301 + t310
    cr = digit_addc(0, cr, t031, &c[4]);
    digit t130, t131;
    t130 = digit_mul(a[1], a[3], &t131);
    digit t220, t221;
    t220 = digit_mul(a[2], a[2], &t221);
    cr += digit_addc(0, c[4], t121, &c[4]);
    cr += digit_addc(0, c[4], t121, &c[4]);
    cr += digit_addc(0, c[4], t031, &c[4]);
    cr += digit_addc(0, c[4], t130, &c[4]);
    cr += digit_addc(0, c[4], t220, &c[4]);
    cr += digit_addc(0, c[4], t130, &c[4]);

    //c5 = t131 + t221 + t230 + t311 + t320
    cr = digit_addc(0, cr, t131, &c[5]);
    digit t230, t231;
    t230 = digit_mul(a[2], a[3], &t231);
    cr += digit_addc(0, c[5], t221, &c[5]);
    cr += digit_addc(0, c[5], t131, &c[5]);
    cr += digit_addc(0, c[5], t230, &c[5]);
    cr += digit_addc(0, c[5], t230, &c[5]);

    //c6 = t231 + t321 + t330
    cr = digit_addc(0, cr, t231, &c[6]);
    digit t330, t331;
    t330 = digit_mul(a[3], a[3], &t331);
    cr += digit_addc(0, c[6], t231, &c[6]);
    cr += digit_addc(0, c[6], t330, &c[6]);

    //c7 = t331
    c[7] = t331 + cr;
}

static void mp_mul256_mod256(
    digit c[4], const digit a[4], const digit b[4])
{
    digit cr = 0;

    //c0 = t000
    digit t000, t001;
    t000 = digit_mul(a[0], b[0], &t001);
    c[0] = t000;

    //c1 = t001 + t010 + t100
    c[1] = t001;
    digit t010, t011;
    t010 = digit_mul(a[0], b[1], &t011);
    digit t100, t101;
    t100 = digit_mul(a[1], b[0], &t101);
    cr += digit_addc(0, c[1], t010, &c[1]);
    cr += digit_addc(0, c[1], t100, &c[1]);

    //c2 = t011 + t020 + t101 + t110 + t200
    cr = digit_addc(0, cr, t011, &c[2]);
    digit t020, t021;
    t020 = digit_mul(a[0], b[2], &t021);
    digit t110, t111;
    t110 = digit_mul(a[1], b[1], &t111);
    digit t201, t200;
    t200 = digit_mul(a[2], b[0], &t201);
    cr += digit_addc(0, c[2], t101, &c[2]);
    cr += digit_addc(0, c[2], t020, &c[2]);
    cr += digit_addc(0, c[2], t110, &c[2]);
    cr += digit_addc(0, c[2], t200, &c[2]);

    //c3 = t021 + t030 + t111 + t120 + t201 + t210 + t300
    c[3] = t021 + cr;
    digit t030;
    t030 = a[0] * b[3];
    digit t120;
    t120 = a[1] * b[2];
    digit t210;
    t210 = a[2] * b[1];
    digit t300;
    t300 = a[3] * b[0];
    c[3] += t111;
    c[3] += t030;
    c[3] += t201;
    c[3] += t120;
    c[3] += t210;
    c[3] += t300;
}

static carry mp_add512(
    digit c[8], const digit a[8], const digit b[8])
{
    carry cr = 0;
    cr = digit_addc(cr, a[0], b[0], &c[0]);
    cr = digit_addc(cr, a[1], b[1], &c[1]);
    cr = digit_addc(cr, a[2], b[2], &c[2]);
    cr = digit_addc(cr, a[3], b[3], &c[3]);
    cr = digit_addc(cr, a[4], b[4], &c[4]);
    cr = digit_addc(cr, a[5], b[5], &c[5]);
    cr = digit_addc(cr, a[6], b[6], &c[6]);
    cr = digit_addc(cr, a[7], b[7], &c[7]);
    return cr;
}

static carry mp_add256(
    digit c[4], const digit a[4], const digit b[4])
{
    carry cr = 0;
    cr = digit_addc(cr, a[0], b[0], &c[0]);
    cr = digit_addc(cr, a[1], b[1], &c[1]);
    cr = digit_addc(cr, a[2], b[2], &c[2]);
    cr = digit_addc(cr, a[3], b[3], &c[3]);
    return cr;
}

static carry mp_sub256(
    digit c[4], const digit a[4], const digit b[4])
{
    carry br = 0;
    br = digit_subb(br, a[0], b[0], &c[0]);
    br = digit_subb(br, a[1], b[1], &c[1]);
    br = digit_subb(br, a[2], b[2], &c[2]);
    br = digit_subb(br, a[3], b[3], &c[3]);
    return br;
}

static void mp_shl(digit a[4], uint8_t count)
{
    a[3] = digit_shl(a[3], a[2], count);
    a[2] = digit_shl(a[2], a[1], count);
    a[1] = digit_shl(a[1], a[0], count);
    a[0] = a[0] << count;
}

#endif
