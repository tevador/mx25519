/* Copyright (c) 2022 tevador <tevador@gmail.com>
 *
 * This file is part of mx25519, which is released under LGPLv3.
 * See LICENSE for full license details.
*/

#ifndef AMD64_SCALARMULT_H
#define AMD64_SCALARMULT_H

#include <mx25519.h>

#include <stdint.h>

MX25519_PRIVATE void mx25519_scalarmult_amd64(uint8_t* q,
    const uint8_t* e,
    const uint8_t* p);

MX25519_PRIVATE void mx25519_scalarmult_amd64x(uint8_t* q,
    const uint8_t* e,
    const uint8_t* p);

#endif
