/* Copyright (c) 2022 tevador <tevador@gmail.com>
 *
 * This file is part of mx25519, which is released under LGPLv3.
 * See LICENSE for full license details.
*/

#ifndef IMPL_H
#define IMPL_H

#include <mx25519.h>

#include <stdint.h>

typedef void scmul_func(uint8_t result[32], const uint8_t key[32], const uint8_t base[32]);

typedef struct mx25519_impl {
    scmul_func* scmul;
    mx25519_type type;
} mx25519_impl;

extern const mx25519_impl* mx25519_impls[4];

#endif
