/* Copyright (c) 2022 tevador <tevador@gmail.com>
 *
 * This file is part of mx25519, which is released under LGPLv3.
 * See LICENSE for full license details.
*/

#ifndef PORTABLE_SCALARMULT_H
#define PORTABLE_SCALARMULT_H

#include <stdint.h>

void mx25519_scalarmult_portable(uint8_t* q,
    const uint8_t* n,
    const uint8_t* p);

#endif
