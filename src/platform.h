/* Copyright (c) 2022 tevador <tevador@gmail.com>
 *
 * This file is part of mx25519, which is released under LGPLv3.
 * See LICENSE for full license details.
*/

#ifndef PLATFORM_H
#define PLATFORM_H

#include <stdint.h>
#include <string.h>

#if defined(_WIN32) || defined(__CYGWIN__)
#define PLATFORM_WIN
#endif

#if defined(_M_IX86) || defined(__i386)
#define PLATFORM_X86
#elif defined(_M_X64) || defined(__x86_64__)
#define PLATFORM_AMD64
#elif defined(_M_ARM64) || defined(__aarch64__)
#define PLATFORM_ARM64
#else

#endif

#ifdef _MSC_VER
#pragma warning(error: 4013) /* calls to undefined functions */
#pragma warning(error: 4090) /* different const qualifiers */
#pragma warning(error: 4133) /* incompatible pointer types */
#pragma warning(disable: 4146) /* unary minus applied to unsigned type */
#endif

#if defined(_M_X64)
#define PLATFORM_X64_INTRIN /* 64-bit intrinsics */
#endif

#if defined(__SIZEOF_INT128__)
typedef unsigned __int128 uint128_t;
#define PLATFORM_UINT128 /* compiler support for 128-bit integers */
#endif

/* force inline */
#if defined(_MSC_VER)
#define FORCE_INLINE __forceinline
#elif defined(__GNUC__) || defined(__clang__)
#define FORCE_INLINE __attribute__((always_inline)) __inline__
#else
#define FORCE_INLINE INLINE
#endif

/* detect native little-endian platforms */
#if (defined(__BYTE_ORDER__) &&                                                \
     (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)) ||                           \
    defined(__LITTLE_ENDIAN__) || defined(__ARMEL__) || defined(__MIPSEL__) || \
    defined(__AARCH64EL__) || defined(__amd64__) || defined(__i386__) ||       \
    defined(_M_IX86) || defined(_M_X64) || defined(_M_AMD64) ||                \
    defined(_M_ARM)
#define PLATFORM_LE
#endif
/* platforms not listed above will use endian-agnostic code */

/* load in little endian format */
static FORCE_INLINE uint64_t platform_load64(const void* src) {
#if defined(PLATFORM_LE)
    uint64_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    const uint8_t* p = (const uint8_t*)src;
    uint64_t w = *p++;
    w |= (uint64_t)(*p++) << 8;
    w |= (uint64_t)(*p++) << 16;
    w |= (uint64_t)(*p++) << 24;
    w |= (uint64_t)(*p++) << 32;
    w |= (uint64_t)(*p++) << 40;
    w |= (uint64_t)(*p++) << 48;
    w |= (uint64_t)(*p++) << 56;
    return w;
#endif
}

/* store in little endian format */
static FORCE_INLINE void platform_store64(void* dst, uint64_t w) {
#if defined(PLATFORM_LE)
    memcpy(dst, &w, sizeof w);
#else
    uint8_t* p = (uint8_t*)dst;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
#endif
}

/* current value of a hardware timer */
uint64_t mx25519_cpu_cycles(void);

/* time in seconds from a fixed point in the past */
double mx25519_wall_clock(void);

#endif
