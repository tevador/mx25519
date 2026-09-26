/* Copyright (c) 2022 tevador <tevador@gmail.com>
 *
 * This file is part of mx25519, which is released under LGPLv3.
 * See LICENSE for full license details.
*/

#include "cpu.h"
#include "platform.h"

#if defined(PLATFORM_X86) || defined(PLATFORM_AMD64)
#define HAVE_CPUID
#ifdef _MSC_VER
#include <intrin.h>
#define cpuid(info, x) __cpuidex(info, x, 0)
#define xgetbv0() ((uint32_t)_xgetbv(0))
#else
#include <cpuid.h>
static void cpuid(uint32_t info[4], uint32_t type) {
    __cpuid_count(type, 0, info[0], info[1], info[2], info[3]);
}
static uint32_t xgetbv0(void) {
    uint32_t eax, edx;
    __asm__ volatile("xgetbv" : "=a"(eax), "=d"(edx) : "c"(0));
    return eax;
}
#endif
#endif

x25519_cpu_cap mx25519_get_cpu_cap() {
    x25519_cpu_cap cap = 0;
#ifdef HAVE_CPUID
    uint32_t info[4];
    cpuid(info, 0);
    uint32_t num_ids = info[0];
    if (num_ids >= 0x00000001) {
        cpuid(info, 0x00000001);
        if ((info[2] & (1 << 28)) && (info[2] & (1 << 27))
            && (xgetbv0() & 6) == 6) {
            cap |= X25519_CPU_CAP_AVX;
        }
    }
    if (num_ids >= 0x00000007) {
        cpuid(info, 0x00000007);
        if (info[1] & (1 << 3)) {
            cap |= X25519_CPU_CAP_BMI1;
        }
        if ((info[1] & (1 << 5)) && (cap & X25519_CPU_CAP_AVX)) {
            cap |= X25519_CPU_CAP_AVX2;
        }
        if (info[1] & (1 << 8)) {
            cap |= X25519_CPU_CAP_MULX;
        }
        if (info[1] & (1 << 19)) {
            cap |= X25519_CPU_CAP_ADX;
        }
    }
#endif
    return cap;
}
