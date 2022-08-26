/* Copyright (c) 2021-2022 tevador <tevador@gmail.com>
 *
 * This file is part of mx25519, which is released under LGPLv3.
 * See LICENSE for full license details.
*/

#include "platform.h"
#include "cpu.h"
#include <time.h>

#if defined(PLATFORM_WIN)
#include <windows.h>
#else
#include <sys/time.h>
#endif

#if defined(_MSC_VER)
#include <intrin.h>
#endif

uint64_t mx25519_cpu_cycles() {
#if defined(PLATFORM_X86) || defined(PLATFORM_AMD64)
    x25519_cpu_cap cpu_cap = mx25519_get_cpu_cap();
    if (cpu_cap & X25519_CPU_CAP_RDTSCP) {
#if defined(_MSC_VER)
        uint32_t aux;
        return __rdtscp(&aux);
#else
        uint32_t lo, hi;
        __asm__ volatile("rdtscp" : "=a"(lo), "=d"(hi) : : "%ecx");
        return ((uint64_t)hi << 32) | lo;
#endif
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
