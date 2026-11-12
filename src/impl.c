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

#include <mx25519.h>

#include "impl.h"
#include "platform.h"
#include "portable/scalarmult.h"
#ifdef IMPL_ARM64
#include "arm64/scalarmult.h"
#endif
#ifdef IMPL_AMD64
#include "amd64/scalarmult.h"
#endif

static const mx25519_impl impl_portable = {
    .scmul = &mx25519_scalarmult_portable,
    .type = MX25519_TYPE_PORTABLE
};

static const mx25519_impl impl_arm64 = {
#if defined(IMPL_ARM64)
    .scmul = &mx25519_scalarmult_arm64,
#else
    .scmul = NULL,
#endif
    .type = MX25519_TYPE_ARM64
};

static const mx25519_impl impl_amd64 = {
#ifdef IMPL_AMD64
    .scmul = &mx25519_scalarmult_amd64,
#else
    .scmul = NULL,
#endif
    .type = MX25519_TYPE_AMD64
};

static const mx25519_impl impl_amd64x = {
#ifdef IMPL_AMD64
    .scmul = &mx25519_scalarmult_amd64x,
#else
    .scmul = NULL,
#endif
    .type = MX25519_TYPE_AMD64X
};

const mx25519_impl* const mx25519_impls[4] = {
    &impl_portable,
    &impl_arm64,
    &impl_amd64,
    &impl_amd64x,
};

#ifdef PLATFORM_DIT
static uint64_t dit_enable(void) {
    uint64_t dit;
    __asm__ volatile("mrs %0, s3_3_c4_c2_5" : "=r"(dit) : : "memory");
    /* Apple recommends a speculation barrier after enabling DIT */
    __asm__ volatile("msr s3_3_c4_c2_5, %0\n\tdsb nsh\n\tisb" : : "r"((uint64_t)1 << 24) : "memory");
    return dit;
}

static void dit_restore(uint64_t dit) {
    __asm__ volatile("msr s3_3_c4_c2_5, %0" : : "r"(dit) : "memory");
}

static void scalarmult_portable_dit(uint8_t* q, const uint8_t* n, const uint8_t* p) {
    uint64_t dit = dit_enable();
    mx25519_scalarmult_portable(q, n, p);
    dit_restore(dit);
}

static const mx25519_impl impl_portable_dit = {
    .scmul = &scalarmult_portable_dit,
    .type = MX25519_TYPE_PORTABLE
};

#ifdef IMPL_ARM64
static void scalarmult_arm64_dit(uint8_t* q, const uint8_t* n, const uint8_t* p) {
    uint64_t dit = dit_enable();
    mx25519_scalarmult_arm64(q, n, p);
    dit_restore(dit);
}
#endif

static const mx25519_impl impl_arm64_dit = {
#ifdef IMPL_ARM64
    .scmul = &scalarmult_arm64_dit,
#else
    .scmul = NULL,
#endif
    .type = MX25519_TYPE_ARM64
};

const mx25519_impl* const mx25519_impls_dit[2] = {
    &impl_portable_dit,
    &impl_arm64_dit,
};
#endif
