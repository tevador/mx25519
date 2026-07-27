/* Copyright (c) 2022 tevador <tevador@gmail.com>
 *
 * This file is part of mx25519, which is released under LGPLv3.
 * See LICENSE for full license details.
*/

#ifndef AMD64_SCALARMULT_H
#define AMD64_SCALARMULT_H

#include <stdint.h>

void mx25519_scalarmult_amd64(uint8_t* q,
    const uint8_t* n,
    const uint8_t* p,
    uint8_t clamp_lo,
    uint8_t clamp_hi);

void mx25519_scalarmult_amd64x(uint8_t* q,
    const uint8_t* n,
    const uint8_t* p,
    uint8_t clamp_lo,
    uint8_t clamp_hi);

#endif
