/* Copyright (c) 2022 tevador <tevador@gmail.com>
 *
 * This file is part of mx25519, which is released under LGPLv3.
 * See LICENSE for full license details.
*/

#include <mx25519.h>

#include "impl.h"
#include "cpu.h"
#include "scalar.h"
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
            && (cap & X25519_CPU_CAP_ADX)  != 0;
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

void mx25519_scmul_base(const mx25519_impl* impl, mx25519_pubkey* result,
    const mx25519_privkey* key)
{
    assert(impl != NULL);
    assert(key != NULL);
    assert(result != NULL);
    impl->scmul(result->data, key->data, x25519_base.data);
}

void mx25519_scmul_key(const mx25519_impl* impl, mx25519_pubkey* result,
    const mx25519_privkey* key, const mx25519_pubkey* pt)
{
    assert(impl != NULL);
    assert(pt != NULL);
    assert(key != NULL);
    assert(result != NULL);
    impl->scmul(result->data, key->data, pt->data);
}

int mx25519_invkey(mx25519_privkey* invkey, const mx25519_privkey keys[],
    size_t num_keys)
{
    assert(invkey != NULL);
    assert(keys != NULL || num_keys == 0);

    /* calculate 8*key[0]*key[1]*... in Montgomery form */
    x25519_scalar_mont prod_mont = mx25519_sc8_mont;

    for (size_t i = 0; i < num_keys; ++i) {
        x25519_scalar key_sc;
        x25519_scalar_mont key_mont;
        mx25519_scalar_unpack(&key_sc, keys[i].data);
        key_sc.v[0] &= 0xfffffffffffffff8;
        key_sc.v[3] &= 0x7fffffffffffffff;
        mx25519_scalar_to_mont(&key_mont, &key_sc);
        mx25519_scalar_mul(&prod_mont, &prod_mont, &key_mont);
    }

    /* invert in Montgomery form */
    mx25519_scalar_inv(&prod_mont, &prod_mont);

    /* convert back from Montgomery form */
    x25519_scalar res;
    mx25519_scalar_from_mont(&res, &prod_mont);

    if (res.v[3] >= 0x1000000000000000) {
        return 1; /* inverse is larger than or equal to 2^252 */
    }

    /* shift left by 3 bits */
    mx25519_scalar_lsh3(&res);

    mx25519_scalar_pack(invkey->data, &res);
    return 0;
}
