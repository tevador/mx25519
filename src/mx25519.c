/* Copyright (c) 2022 tevador <tevador@gmail.com>
 *
 * This file is part of mx25519, which is released under LGPLv3.
 * See LICENSE for full license details.
*/

#include <mx25519.h>

#include "impl.h"
#include "cpu.h"
#include "platform.h"

#include <stdint.h>
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
#if defined(PLATFORM_ARM64)
        return true;
#else
        return false;
#endif
    }
    if (impl == MX25519_TYPE_AMD64) {
#if defined(PLATFORM_AMD64)
        return true;
#else
        return false;
#endif
    }
    if (impl == MX25519_TYPE_AMD64X) {
#if defined(PLATFORM_AMD64)
        x25519_cpu_cap cap = mx25519_get_cpu_cap();
        return (cap & X25519_CPU_CAP_MULX) != 0
            && (cap & X25519_CPU_CAP_ADX)  != 0
            && (cap & X25519_CPU_CAP_AVX2) != 0;
#else
        return false;
#endif
    }
    return false;
}

static mx25519_type select_best_impl(void) {
#if defined(PLATFORM_AMD64)
    if (impl_supported(MX25519_TYPE_AMD64X)) {
        return MX25519_TYPE_AMD64X;
    }
    return MX25519_TYPE_AMD64;
#elif defined(PLATFORM_ARM64)
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

void mx25519_key_clamp_rfc7748(mx25519_privkey* key)
{
    assert(key != NULL);

    key->data[0] &= 248;
    key->data[31] &= 127;
    key->data[31] |= 64;
}
