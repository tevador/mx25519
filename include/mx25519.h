/* Copyright (c) 2022 tevador <tevador@gmail.com>
 *
 * This file is part of mx25519, which is released under LGPLv3.
 * See LICENSE for full license details.
*/

#ifndef MX25519_H
#define MX25519_H

#include <stdint.h>
#include <stddef.h>

/*
 * X25519 scalar (private key).
 * All private keys are implicitly multiples of 8 as the library only uses
 * bits 3-254. Bits 0-2 and 255 are internally set to 0.
 * Note that the key clamping procedure of this library differs from RFC 7748
 * by not setting the value of bit 254 to 1. This is done to support inverted
 * keys, which might have a zero bit in that position.
 */
typedef struct mx25519_privkey {
    uint8_t data[32];
} mx25519_privkey;

/*
 * X25519 X-coordinate (public key).
 */
typedef struct mx25519_pubkey {
    uint8_t data[32];
} mx25519_pubkey;

/*
 * Opaque struct holding a scalar multiplication implementation.
 */
typedef struct mx25519_impl mx25519_impl;

/*
 * Implementation types.
 */
typedef enum mx25519_type {
    MX25519_TYPE_AUTO = -1, /* select automatically */
    MX25519_TYPE_PORTABLE,  /* portable C implementation */
    MX25519_TYPE_ARM64,     /* ARM64 assembly */
    MX25519_TYPE_AMD64,     /* AMD64 assembly */
    MX25519_TYPE_AMD64X,    /* AMD64 assembly with MULX+ADX */
} mx25519_type;

#if defined(_WIN32) || defined(__CYGWIN__)
#define MX25519_WIN
#endif

/* Shared/static library definitions */
#ifdef MX25519_WIN
    #ifdef MX25519_SHARED
        #define MX25519_API __declspec(dllexport)
    #elif !defined(MX25519_STATIC)
        #define MX25519_API __declspec(dllimport)
    #else
        #define MX25519_API
    #endif
    #define MX25519_PRIVATE
#else
    #ifdef MX25519_SHARED
        #define MX25519_API __attribute__ ((visibility ("default")))
    #else
        #define MX25519_API __attribute__ ((visibility ("hidden")))
    #endif
    #define MX25519_PRIVATE __attribute__ ((visibility ("hidden")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Selects an implementation.
 *
 * @param type is the requested implementation type. If MX25519_TYPE_AUTO
 *        is specified, the best implementation for the current machine
 *        will be selected.
 *
 * @return pointer to an internal implementation structure. Returns NULL
 *         if the requested implementation is not supported.
 */
MX25519_API const mx25519_impl* mx25519_select_impl(mx25519_type type);

/*
 * @param impl is a pointer to an implementation. Must not be NULL.
 *
 * @return the type of the implementation.
 */
MX25519_API mx25519_type mx25519_impl_type(const mx25519_impl* impl);

/*
 * Calculates x(key*G), where G is the generator point of Curve25519.
 *
 * @param impl is a pointer to an implementation. Must not be NULL.
 * @param result is the pointer where the resulting public key will be stored.
 *        Must not be NULL.
 * @param key is a pointer to the private key. Must not be NULL.
 */
MX25519_API void mx25519_scmul_base(const mx25519_impl* impl,
    mx25519_pubkey* result, const mx25519_privkey* key);

/*
 * Calculates x(key*P), where P is a given public key.
 *
 * @param impl is a pointer to an implementation. Must not be NULL.
 * @param result is the pointer where the resulting public key will be stored.
 *        Must not be NULL.
 * @param key is a pointer to the private key. Must not be NULL.
 * @param p is a pointer to the base point P. Must not be NULL.
 */
MX25519_API void mx25519_scmul_key(const mx25519_impl* impl, mx25519_pubkey* result,
    const mx25519_privkey* key, const mx25519_pubkey* p);

/*
 * Calculates invkey = 1/(key[0]*key[1]*...). This private key can be used
 * to remove the respective private key components from a public key.
 * (This only works for public keys that lie on Curve25519 and not on
 * its quadratic twist.)
 *
 * @param invkey is the pointer where the resulting private key will be stored.
 *        Must not be NULL.
 * @param key is an array of private keys to invert. Must not be NULL.
 * @param num_keys is the number of private keys in the array.
 *
 * @return zero on success, a non-zero value in case of a failure. A failure
 *         can occur with a probability of approx. 2^(-124).
 */
MX25519_API int mx25519_invkey(mx25519_privkey* invkey,
    const mx25519_privkey keys[], size_t num_keys);

#ifdef __cplusplus
}
#endif

#endif
