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

#ifndef PLATFORM_H
#define PLATFORM_H

#include <stdint.h>

#if defined(_WIN32) || defined(__CYGWIN__)
#define PLATFORM_WIN
#endif

#if defined(_M_IX86) || defined(__i386)
#define PLATFORM_X86
#elif defined(_M_X64) || defined(__x86_64__)
#define PLATFORM_AMD64
#elif defined(_M_ARM64) || defined(__aarch64__)
#define PLATFORM_ARM64
#endif

#if !defined(MX25519_NO_COPYLEFT)
#if defined(PLATFORM_ARM64)
#define IMPL_ARM64
#elif defined(PLATFORM_AMD64)
#define IMPL_AMD64
#endif
#endif

#ifdef _MSC_VER
#pragma warning(error: 4013) /* calls to undefined functions */
#pragma warning(error: 4090) /* different const qualifiers */
#pragma warning(error: 4133) /* incompatible pointer types */
#pragma warning(disable: 4146) /* unary minus applied to unsigned type */
#endif

/* current value of a timer */
uint64_t mx25519_cpu_cycles(void);

/* time in seconds from a fixed point in the past */
double mx25519_wall_clock(void);

#endif
