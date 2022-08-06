/* Copyright (c) 2022 tevador <tevador@gmail.com>
 *
 * This file is part of mx25519, which is released under LGPLv3.
 * See LICENSE for full license details.
*/

#ifndef SCALAR_H
#define SCALAR_H

#include "digit.h"

#include <stdint.h>

typedef struct x25519_scalar {
    digit v[4];
} x25519_scalar;

typedef struct x25519_scalar_mont {
    digit v[4];
} x25519_scalar_mont;

extern const x25519_scalar_mont mx25519_sc8_mont;

void mx25519_scalar_unpack(x25519_scalar* sc, const uint8_t key[32]);
void mx25519_scalar_pack(uint8_t key[32], const x25519_scalar* sc);

void mx25519_scalar_to_mont(x25519_scalar_mont* sc_mont, const x25519_scalar* sc);
void mx25519_scalar_from_mont(x25519_scalar* sc, const x25519_scalar_mont* sc_mont);

void mx25519_scalar_mul(x25519_scalar_mont* c, const x25519_scalar_mont* a, const x25519_scalar_mont* b);

void mx25519_scalar_inv(x25519_scalar_mont* inv, const x25519_scalar_mont* sc);

void mx25519_scalar_lsh3(x25519_scalar* sc);

#endif
