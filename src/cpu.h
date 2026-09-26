/* Copyright (c) 2022 tevador <tevador@gmail.com>
 *
 * This file is part of mx25519, which is released under LGPLv3.
 * See LICENSE for full license details.
*/

#ifndef CPU_H
#define CPU_H

#include <mx25519.h>
#include <stdbool.h>

typedef enum x25519_cpu_cap {
    X25519_CPU_CAP_AVX = 2,
    X25519_CPU_CAP_AVX2 = 4,
    X25519_CPU_CAP_MULX = 8,
    X25519_CPU_CAP_ADX = 16,
    X25519_CPU_CAP_BMI1 = 32,
} x25519_cpu_cap;

MX25519_PRIVATE x25519_cpu_cap mx25519_get_cpu_cap(void);

#endif
