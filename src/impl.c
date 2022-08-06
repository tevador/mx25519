/* Copyright (c) 2022 tevador <tevador@gmail.com>
 *
 * This file is part of mx25519, which is released under LGPLv3.
 * See LICENSE for full license details.
*/

#include <mx25519.h>

#include "impl.h"
#include "platform.h"
#include "portable/scalarmult.h"
#ifdef PLATFORM_ARM64
#include "arm64/scalarmult.h"
#endif
#ifdef PLATFORM_AMD64
#include "amd64/scalarmult.h"
#endif

static const mx25519_impl impl_portable = {
    .scmul = &mx25519_scalarmult_portable,
    .type = MX25519_TYPE_PORTABLE
};

static const mx25519_impl impl_arm64 = {
#if defined(PLATFORM_ARM64)
    .scmul = &mx25519_scalarmult_arm64,
#else
    .scmul = NULL,
#endif
    .type = MX25519_TYPE_ARM64
};

static const mx25519_impl impl_amd64 = {
#ifdef PLATFORM_AMD64
    .scmul = &mx25519_scalarmult_amd64,
#else
    .scmul = NULL,
#endif
    .type = MX25519_TYPE_AMD64
};

static const mx25519_impl impl_amd64x = {
#ifdef PLATFORM_AMD64
    .scmul = &mx25519_scalarmult_amd64x,
#else
    .scmul = NULL,
#endif
    .type = MX25519_TYPE_AMD64X
};

const mx25519_impl* mx25519_impls[4] = {
    &impl_portable,
    &impl_arm64,
    &impl_amd64,
    &impl_amd64x,
};
