/* Copyright (c) 2022-2026 tevador <tevador@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE
#endif

#include "cpu.h"
#include "platform.h"

#if defined(IMPL_AMD64)
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

#if defined(PLATFORM_DIT) && defined(__APPLE__)
#include <sys/sysctl.h>
#elif defined(PLATFORM_DIT)
#include <sys/auxv.h>
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
#if defined(PLATFORM_DIT) && defined(__APPLE__)
    int dit = 0;
    size_t size = sizeof(dit);
    if (sysctlbyname("hw.optional.arm.FEAT_DIT", &dit, &size, NULL, 0) == 0 && dit) {
        cap |= X25519_CPU_CAP_DIT;
    }
#elif defined(PLATFORM_DIT)
    if (getauxval(AT_HWCAP) & (1 << 24)) {
        cap |= X25519_CPU_CAP_DIT;
    }
#endif
    return cap;
}
