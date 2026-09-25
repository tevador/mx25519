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

/* current value of a hardware timer */
uint64_t mx25519_cpu_cycles(void);

/* time in seconds from a fixed point in the past */
double mx25519_wall_clock(void);

#endif
