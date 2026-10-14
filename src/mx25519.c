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
#include "cpu.h"
#include "platform.h"

#include <stdbool.h>
#include <assert.h>

static const mx25519_pubkey x25519_base = {
    .data = { 9 }
};

static bool impl_supported(mx25519_type impl) {
    if (impl == MX25519_TYPE_PORTABLE) {
        return true;
    }
    if (impl == MX25519_TYPE_ARM64) {
#if defined(IMPL_ARM64)
        return true;
#else
        return false;
#endif
    }
    if (impl == MX25519_TYPE_AMD64) {
#if defined(IMPL_AMD64)
        return true;
#else
        return false;
#endif
    }
    if (impl == MX25519_TYPE_AMD64X) {
#if defined(IMPL_AMD64)
        x25519_cpu_cap cap = mx25519_get_cpu_cap();
        return (cap & X25519_CPU_CAP_BMI1) != 0
            && (cap & X25519_CPU_CAP_MULX) != 0
            && (cap & X25519_CPU_CAP_ADX)  != 0
            && (cap & X25519_CPU_CAP_AVX2) != 0;
#else
        return false;
#endif
    }
    return false;
}

static mx25519_type select_best_impl(void) {
#if defined(IMPL_AMD64)
    if (impl_supported(MX25519_TYPE_AMD64X)) {
        return MX25519_TYPE_AMD64X;
    }
    return MX25519_TYPE_AMD64;
#elif defined(IMPL_ARM64)
    return MX25519_TYPE_ARM64;
#else
    return MX25519_TYPE_PORTABLE;
#endif
}

static inline void dispatch(const mx25519_impl* impl,
    mx25519_pubkey* result, const mx25519_privkey* key,
    const mx25519_pubkey* pt)
{
    assert(impl != NULL);
    assert(pt != NULL);
    assert(key != NULL);
    assert(result != NULL);
    assert(impl->scmul != NULL);
    assert(impl->type <= MX25519_TYPE_AMD64X);

    /* dispatch */
    impl->scmul(result->data, key->data, pt->data);
}

const mx25519_impl* mx25519_select_impl(mx25519_type type)
{
    if (type == MX25519_TYPE_AUTO) {
        type = select_best_impl();
    }
    else if (!impl_supported(type)) {
        return NULL;
    }
    assert(type >= 0 && type < 4);
    return mx25519_impls[type];
}

mx25519_type mx25519_impl_type(const mx25519_impl* impl)
{
    assert(impl != NULL);
    return impl->type;
}

void mx25519_scmul_base_unclamped(const mx25519_impl* impl,
    mx25519_pubkey* result, const mx25519_privkey* key)
{
    dispatch(impl, result, key, &x25519_base);
}

void mx25519_scmul_key_unclamped(const mx25519_impl* impl,
    mx25519_pubkey* result, const mx25519_privkey* key,
    const mx25519_pubkey* pt)
{
    dispatch(impl, result, key, pt);
}
