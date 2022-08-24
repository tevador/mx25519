/* Copyright (c) 2022 tevador <tevador@gmail.com>
 *
 * This file is part of mx25519, which is released under LGPLv3.
 * See LICENSE for full license details.
*/

#include "scalar.h"
#include "platform.h"

#include "mp_ops.h"

#define U256_CONST(d3, d2, d1, d0) {{(d0), (d1), (d2), (d3)}}

/* l = 2^252 + 27742317777372353535851937790883648493 */
static const x25519_scalar group_order =
    U256_CONST(
        0x1000000000000000, 0x0000000000000000,
        0x14DEF9DEA2F79CD6, 0x5812631A5CF5D3ED);

/* the Montgomery form of 8 */
const x25519_scalar_mont mx25519_sc8_mont =
    U256_CONST(
        0x0FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFF5,
        0xA5620A8D272931AA, 0x4EE0D5EBE20BDD6D);

/* 2^512 mod l */
static const x25519_scalar_mont mont_modulus =
    U256_CONST(
        0x0399411B7C309A3D, 0xCEEC73D217F5BE65,
        0xD00E1BA768859347, 0xA40611E3449C0F01);

/* -l^(-1) mod 2^256 */
static const x25519_scalar_mont mont_rprime =
    U256_CONST(
        0x9DB6C6F26FE91836, 0x14E75438FFA36BEA,
        0xB1A206F2FDBA84FF, 0xD2B51DA312547E1B);

/* Mongomery reduction of a 512-bit product */
static void scalar_reduce_mont(digit res[4], const digit prod[8]) {
    digit mask;
    digit quot[4];
    digit temp[8];
    carry cout = 0, bout = 0;

    mp_mul256_mod256(quot, prod, mont_rprime.v); // quot = prod * r' mod 2^256
    mp_mul256(temp, quot, group_order.v);        // temp = quot * l
    cout = mp_add512(temp, temp, prod);          // temp = temp + prod

    //res = temp / 2^256
    res[0] = temp[4];
    res[1] = temp[5];
    res[2] = temp[6];
    res[3] = temp[7];

    //constant-time subtraction of l
    bout = mp_sub256(res, res, group_order.v);
    mask = (digit)cout - (digit)bout; //mask = 0xFF..FF if res < l

    temp[0] = group_order.v[0] & mask;
    temp[1] = group_order.v[1] & mask;
    temp[2] = group_order.v[2] & mask;
    temp[3] = group_order.v[3] & mask;

    mp_add256(res, res, temp);
}

void mx25519_scalar_unpack(x25519_scalar* sc, const uint8_t key[32])
{
    sc->v[0] = digit_load(key + 0);
    sc->v[1] = digit_load(key + 8);
    sc->v[2] = digit_load(key + 16);
    sc->v[3] = digit_load(key + 24);
}

void mx25519_scalar_pack(uint8_t key[32], const x25519_scalar* sc)
{
    digit_store(key + 0, sc->v[0]);
    digit_store(key + 8, sc->v[1]);
    digit_store(key + 16, sc->v[2]);
    digit_store(key + 24, sc->v[3]);
}

/* Converts a scalar to the Mongtgomery representation */
void mx25519_scalar_to_mont(x25519_scalar_mont* sc_mont, const x25519_scalar* sc)
{
    digit prod[8];
    mp_mul256(prod, sc->v, mont_modulus.v);
    scalar_reduce_mont(sc_mont->v, prod);
}

/* Converts a scalar from the Montgomery representation */
void mx25519_scalar_from_mont(x25519_scalar* sc, const x25519_scalar_mont* sc_mont)
{
    digit prod[8];
    prod[0] = sc_mont->v[0];
    prod[1] = sc_mont->v[1];
    prod[2] = sc_mont->v[2];
    prod[3] = sc_mont->v[3];
    prod[4] = 0;
    prod[5] = 0;
    prod[6] = 0;
    prod[7] = 0;
    scalar_reduce_mont(sc->v, prod);
}

void mx25519_scalar_lsh3(x25519_scalar* sc)
{
    mp_shl(sc->v, 3);
}

void mx25519_scalar_mul(x25519_scalar_mont* c, const x25519_scalar_mont* a,
    const x25519_scalar_mont* b)
{
    digit prod[8];
    mp_mul256(prod, a->v, b->v);
    scalar_reduce_mont(c->v, prod);
}

#define scalar_mul mx25519_scalar_mul

static void scalar_sqr(x25519_scalar_mont* c, const x25519_scalar_mont* a)
{
    digit prod[8];
    mp_sqr256(prod, a->v);
    scalar_reduce_mont(c->v, prod);
}

#define scalar_nsqr_mul(res, n, mul) do { \
    for (int i = 0; i < n; ++i) scalar_sqr(res, res); \
    scalar_mul(res, res, mul); \
} while (0)

/*
* Scalar inversion mod l
* https://briansmith.org/ecc-inversion-addition-chains-01#curve25519_scalar_inversion
*/
void mx25519_scalar_inv(x25519_scalar_mont* inv, const x25519_scalar_mont* sc)
{
    x25519_scalar_mont _1 = *sc;
    x25519_scalar_mont _10;
    x25519_scalar_mont _100;
    x25519_scalar_mont _11;
    x25519_scalar_mont _101;
    x25519_scalar_mont _111;
    x25519_scalar_mont _1001;
    x25519_scalar_mont _1011;
    x25519_scalar_mont _1111;
    scalar_sqr(&_10, &_1);
    scalar_sqr(&_100, &_10);
    scalar_mul(&_11, &_10, &_1);
    scalar_mul(&_101, &_10, &_11);
    scalar_mul(&_111, &_10, &_101);
    scalar_mul(&_1001, &_10, &_111);
    scalar_mul(&_1011, &_10, &_1001);
    scalar_mul(&_1111, &_100, &_1011);

    scalar_mul(inv, &_1, &_1111); //inv = _10000

    scalar_nsqr_mul(inv, 123 + 3, &_101);
    scalar_nsqr_mul(inv, 2 + 2, &_11);
    scalar_nsqr_mul(inv, 1 + 4, &_1111);
    scalar_nsqr_mul(inv, 1 + 4, &_1111);
    scalar_nsqr_mul(inv, 4, &_1001);
    scalar_nsqr_mul(inv, 2, &_11);
    scalar_nsqr_mul(inv, 1 + 4, &_1111);
    scalar_nsqr_mul(inv, 1 + 3, &_101);
    scalar_nsqr_mul(inv, 3 + 3, &_101);
    scalar_nsqr_mul(inv, 3, &_111);
    scalar_nsqr_mul(inv, 1 + 4, &_1111);
    scalar_nsqr_mul(inv, 2 + 3, &_111);
    scalar_nsqr_mul(inv, 2 + 2, &_11);
    scalar_nsqr_mul(inv, 1 + 4, &_1011);
    scalar_nsqr_mul(inv, 2 + 4, &_1011);
    scalar_nsqr_mul(inv, 6 + 4, &_1001);
    scalar_nsqr_mul(inv, 2 + 2, &_11);
    scalar_nsqr_mul(inv, 3 + 2, &_11);
    scalar_nsqr_mul(inv, 3 + 2, &_11);
    scalar_nsqr_mul(inv, 1 + 4, &_1001);
    scalar_nsqr_mul(inv, 1 + 3, &_111);
    scalar_nsqr_mul(inv, 2 + 4, &_1111);
    scalar_nsqr_mul(inv, 1 + 4, &_1011);
    scalar_nsqr_mul(inv, 3, &_101);
    scalar_nsqr_mul(inv, 2 + 4, &_1111);
    scalar_nsqr_mul(inv, 3, &_101);
    scalar_nsqr_mul(inv, 1 + 2, &_11);
}
