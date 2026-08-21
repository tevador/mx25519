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
 * Unless explicitly using an  "_unclamped" function, all private keys are
 * "clamped": bits 0-2 and 255 are internally set to 0, and bit 254 is set to 1.
 * This behavior matches RFC 7748. When using an "_unclamped" function, the key
 * clamping is controlled by the value of passed `mx25519_unclamp_flags`.
 * The unclamped behavior does *not* match RFC 7748, and is not compatible with
 * programs which are RFC 7748 compliant. Unclamped operations are done to
 * A) support inverted keys, which might have a zero bit in the 254th position,
 * and B) support ECDH for existing legacy keys, which may not be clamped.
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
 * The private key is treated as a 255-bit little-endian integer.
 * Bit 255 is ignored. No clamping is applied to bits 0-254.
 *
 * @param impl is a pointer to an implementation. Must not be NULL.
 * @param result is the pointer where the resulting public key will be stored.
 *        Must not be NULL.
 * @param key is a pointer to the private key. Must not be NULL.
 */
MX25519_API void mx25519_scmul_base_unclamped(const mx25519_impl* impl,
    mx25519_pubkey* result, const mx25519_privkey* key);

/*
 * Calculates x(key*P), where P is a given public key.
 * The private key is treated as a 255-bit little-endian integer.
 * Bit 255 is ignored. No clamping is applied to bits 0-254.
 *
 * @param impl is a pointer to an implementation. Must not be NULL.
 * @param result is the pointer where the resulting public key will be stored.
 *        Must not be NULL.
 * @param key is a pointer to the private key. Must not be NULL.
 * @param p is a pointer to the base point P. Must not be NULL.
 */
MX25519_API void mx25519_scmul_key_unclamped(const mx25519_impl* impl,
    mx25519_pubkey* result, const mx25519_privkey* key,
    const mx25519_pubkey* p);

/*
 * Applies RFC 7748 clamping to the key.
 * Should be called before mx25519_scmul_base_unclamped and
 * mx25519_scmul_key_unclamped if RFC 7748 compliance is required.
 *
 * @param key is a pointer to the private key. Must not be NULL.
 */
MX25519_API void mx25519_key_clamp_rfc7748(mx25519_privkey* key);

#ifdef __cplusplus
}
#endif

#endif
