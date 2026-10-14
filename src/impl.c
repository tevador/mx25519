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
