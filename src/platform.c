/* Copyright (c) 2021-2022 tevador <tevador@gmail.com>
 *
 * This file is part of mx25519, which is released under LGPLv3.
 * See LICENSE for full license details.
*/

#include "platform.h"
#include <time.h>

#if defined(PLATFORM_WIN)
#include <windows.h>
#else
#include <sys/time.h>
#endif

#if defined(_MSC_VER)
#include <intrin.h>
#elif defined(PLATFORM_X86) || defined(PLATFORM_AMD64)
#include <cpuid.h>
#include <x86intrin.h>
#endif

uint64_t mx25519_cpu_cycles() {
#if defined(PLATFORM_X86) || defined(PLATFORM_AMD64)
    /* CPUID is used only to serialize the pipeline before reading the TSC.
       Its result is checked so that the compiler cannot discard the call. */
#if defined(_MSC_VER)
    int info[4];
    __cpuid(info, 0);
    unsigned int max_leaf = (unsigned int)info[0];
#else
    unsigned int max_leaf, b, c, d;
    __cpuid(0, max_leaf, b, c, d);
#endif
    if (max_leaf >= 1) {
        return __rdtsc();
    }
#endif
#if defined(PLATFORM_ARM64)
    uint64_t vct;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(vct));
    return vct;
#endif
    return clock(); /* fallback */
}

double mx25519_wall_clock() {
#ifdef PLATFORM_WIN
    static double freq = 0;
    if (freq == 0) {
        LARGE_INTEGER freq_long;
        if (!QueryPerformanceFrequency(&freq_long)) {
            return 0;
        }
        freq = freq_long.QuadPart;
    }
    LARGE_INTEGER time;
    if (!QueryPerformanceCounter(&time)) {
        return 0;
    }
    return time.QuadPart / freq;
#else
    struct timeval time;
    if (gettimeofday(&time, NULL) != 0) {
        return 0;
    }
    return (double)time.tv_sec + (double)time.tv_usec * 1.0e-6;
#endif
}
