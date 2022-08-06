/* Copyright (c) 2022 tevador <tevador@gmail.com>
 *
 * This file is part of mx25519, which is released under LGPLv3.
 * See LICENSE for full license details.
*/

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <mx25519.h>

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

typedef bool test_func();
static int test_no = 0;

#define RUN_TEST(x) run_test(#x, &x)

static void run_test(const char* name, test_func* func) {
    printf("[%2i] %-40s ... ", ++test_no, name);
    printf(func() ? "PASSED\n" : "SKIPPED\n");
}

/* RFC 7748 test vectors */
/* the second most significant bit of each private key was set to 1 to match the RFC results */
static const char rfc7748_sc1[] = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4";
static const char rfc7748_pt1[] = "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c";
static const char rfc7748_re1[] = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552";

static const char rfc7748_sc2[] = "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba4d";
static const char rfc7748_pt2[] = "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493";
static const char rfc7748_re2[] = "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957";

/* base point >2^255-19 */
static const char test_sc3[] = "a92b2c3964e188a899d6f74b99679013b0a2510b5a6a0a90739e444b23f7bae6";
static const char test_pt3[] = "f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
static const char test_re3[] = "18b1569101d55e0e7e8527a73e27d43393a2d4ec73e67078064bc2a56dcb5860";

/* scalar with bit 254 set to 0 */
const char test_sc4[] = "abc58a54782e87c7052458c2caa461aa27024fb08801ad4bb376b880e449da88";
const char test_pt4[] = "08558f428dff0dc8ee4bebf2408982cf65538a3ae57dffe4f49f43f5506ccd09";
const char test_re4[] = "cd178e864e4f3dd3f5e945c04b87825b84d8a224b6c240784515c5f87af27647";

/* DH key exchange tests */
static const char rfc7748_alice_priv[] = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c6a";
static const char rfc7748_alice_pub[] = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
static const char rfc7748_bob_priv[] = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
static const char rfc7748_bob_pub[] = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
static const char rfc7748_shared[] = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

/* scalar inversion tests */
const char inv_1[] = "c87be1164f29370883d6e6e89bed9c3e00000000000000000000000000000030";
const char inv_priv1[] = "d365dfc2872dc2c49e0165cd9a41141cbd103e7d6a0e281751c2c2955facb87d";
const char inv_priv2[] = "a242507ec0109f853f0c473b755af057e697eb73af42ba981ecbc39eb2135b43";
const char inv_priv3[] = "943df7d7fd479a904d113e14a1b47c7c3a82ca8dc04af57ca42c7d43baa7f327";
const char inv_pubkey[] = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";

static const mx25519_impl* impl;

static inline void output_hex(const uint8_t* data, int length) {
    for (int i = 0; i < length; ++i)
        printf("%02x", data[i]);
}

static inline char parse_nibble(char hex) {
    hex &= ~0x20;
    return (hex & 0x40) ? hex - ('A' - 10) : hex & 0xf;
}

static inline void hex2bin(const char* in, int length, uint8_t* out) {
    for (int i = 0; i < length; i += 2) {
        char nibble1 = parse_nibble(*in++);
        char nibble2 = parse_nibble(*in++);
        *out++ = (uint8_t)nibble1 << 4 | (uint8_t)nibble2;
    }
}

#define KEY_SIZE 32
#define load_key(key, hex) hex2bin(hex, 2 * KEY_SIZE, key.v)

static inline bool equals_hex(const void* val, const char* hex) {
    char reference[KEY_SIZE];
    hex2bin(hex, 2 * KEY_SIZE, reference);
    return memcmp(val, reference, sizeof(reference)) == 0;
}

static bool check_scmul(const char* key_hex, const char* pt_hex, const char* res_hex) {
    assert(impl != NULL);
    mx25519_privkey key;
    load_key(key, key_hex);
    mx25519_pubkey pt;
    load_key(pt, pt_hex);
    mx25519_pubkey res;
    mx25519_scmul(impl , &res, &key, &pt);
    return equals_hex(res.v, res_hex);
}

static void check_dh() {
    assert(impl != NULL);
    mx25519_privkey alice_priv, bob_priv;
    load_key(alice_priv, rfc7748_alice_priv);
    load_key(bob_priv, rfc7748_bob_priv);
    mx25519_pubkey alice_pub, bob_pub;
    mx25519_scmul_base(impl, &alice_pub, &alice_priv);
    assert(equals_hex(&alice_pub, rfc7748_alice_pub));
    mx25519_scmul_base(impl, &bob_pub, &bob_priv);
    assert(equals_hex(&bob_pub, rfc7748_bob_pub));
    mx25519_pubkey alice_shared, bob_shared;
    mx25519_scmul(impl, &alice_shared, &alice_priv, &bob_pub);
    assert(equals_hex(&alice_shared, rfc7748_shared));
    mx25519_scmul(impl, &bob_shared, &bob_priv, &alice_pub);
    assert(equals_hex(&bob_shared, rfc7748_shared));
}

static bool test_select_auto() {
    impl = mx25519_select_impl(MX25519_TYPE_AUTO);
    assert(impl != NULL);
    mx25519_type type = mx25519_impl_type(impl);
    return true;
}

static bool test_select_portable() {
    impl = mx25519_select_impl(MX25519_TYPE_PORTABLE);
    assert(impl != NULL);
    return true;
}

static bool test_type_portable() {
    mx25519_type type = mx25519_impl_type(impl);
    assert(type == MX25519_TYPE_PORTABLE);
    return true;
}

static bool test_scmul1_portable() {
    assert(check_scmul(rfc7748_sc1, rfc7748_pt1, rfc7748_re1));
    return true;
}

static bool test_scmul2_portable() {
    assert(check_scmul(rfc7748_sc2, rfc7748_pt2, rfc7748_re2));
    return true;
}

static bool test_scmul3_portable() {
    assert(check_scmul(test_sc3, test_pt3, test_re3));
    return true;
}

static bool test_scmul4_portable() {
    assert(check_scmul(test_sc4, test_pt4, test_re4));
    return true;
}

static bool test_dh_portable() {
    check_dh();
    return true;
}

static bool test_invert1() {
    mx25519_privkey invkey;
    mx25519_invkey(&invkey, NULL, 0);
    assert(equals_hex(&invkey, inv_1));
    mx25519_pubkey res;
    load_key(res, inv_pubkey);
    mx25519_scmul(impl, &res, &invkey, &res);
    assert(equals_hex(&res, inv_pubkey));
    return true;
}

static bool test_invert2() {
#define NUM_KEYS 3
    mx25519_privkey keys[NUM_KEYS];
    load_key(keys[0], inv_priv1);
    load_key(keys[1], inv_priv2);
    load_key(keys[2], inv_priv3);
    mx25519_pubkey res;
    load_key(res, inv_pubkey);
    mx25519_scmul(impl, &res, &keys[0], &res);
    mx25519_scmul(impl, &res, &keys[1], &res);
    mx25519_scmul(impl, &res, &keys[2], &res);
    mx25519_privkey invkey;
    int fail = mx25519_invkey(&invkey, keys, NUM_KEYS);
    assert(!fail);
    mx25519_scmul(impl, &res, &invkey, &res);
    assert(equals_hex(&res, inv_pubkey));
#undef NUM_KEYS
    return true;
}

static bool test_select_arm64() {
    impl = mx25519_select_impl(MX25519_TYPE_ARM64);
    return true;
}

static bool test_type_arm64() {
    if (impl == NULL) {
        return false;
    }
    mx25519_type type = mx25519_impl_type(impl);
    assert(type == MX25519_TYPE_ARM64);
    return true;
}

static bool test_scmul1_arm64() {
    if (impl == NULL) {
        return false;
    }
    assert(check_scmul(rfc7748_sc1, rfc7748_pt1, rfc7748_re1));
    return true;
}

static bool test_scmul2_arm64() {
    if (impl == NULL) {
        return false;
    }
    assert(check_scmul(rfc7748_sc2, rfc7748_pt2, rfc7748_re2));
    return true;
}

static bool test_scmul3_arm64() {
    if (impl == NULL) {
        return false;
    }
    assert(check_scmul(rfc7748_alice_priv, test_pt3, rfc7748_alice_pub));
    return true;
}

static bool test_scmul4_arm64() {
    if (impl == NULL) {
        return false;
    }
    assert(check_scmul(test_sc4, test_pt4, test_re4));
    return true;
}

static bool test_dh_arm64() {
    if (impl == NULL) {
        return false;
    }
    check_dh();
    return true;
}

static bool test_select_amd64() {
    impl = mx25519_select_impl(MX25519_TYPE_AMD64);
    return true;
}

static bool test_type_amd64() {
    if (impl == NULL) {
        return false;
    }
    mx25519_type type = mx25519_impl_type(impl);
    assert(type == MX25519_TYPE_AMD64);
    return true;
}

static bool test_scmul1_amd64() {
    if (impl == NULL) {
        return false;
    }
    assert(check_scmul(rfc7748_sc1, rfc7748_pt1, rfc7748_re1));
    return true;
}

static bool test_scmul2_amd64() {
    if (impl == NULL) {
        return false;
    }
    assert(check_scmul(rfc7748_sc2, rfc7748_pt2, rfc7748_re2));
    return true;
}

static bool test_scmul3_amd64() {
    if (impl == NULL) {
        return false;
    }
    assert(check_scmul(rfc7748_alice_priv, test_pt3, rfc7748_alice_pub));
    return true;
}

static bool test_scmul4_amd64() {
    if (impl == NULL) {
        return false;
    }
    assert(check_scmul(test_sc4, test_pt4, test_re4));
    return true;
}

static bool test_dh_amd64() {
    if (impl == NULL) {
        return false;
    }
    check_dh();
    return true;
}

static bool test_select_amd64x() {
    impl = mx25519_select_impl(MX25519_TYPE_AMD64X);
    return true;
}

static bool test_type_amd64x() {
    if (impl == NULL) {
        return false;
    }
    mx25519_type type = mx25519_impl_type(impl);
    assert(type == MX25519_TYPE_AMD64X);
    return true;
}

static bool test_scmul1_amd64x() {
    if (impl == NULL) {
        return false;
    }
    assert(check_scmul(rfc7748_sc1, rfc7748_pt1, rfc7748_re1));
    return true;
}

static bool test_scmul2_amd64x() {
    if (impl == NULL) {
        return false;
    }
    assert(check_scmul(rfc7748_sc2, rfc7748_pt2, rfc7748_re2));
    return true;
}

static bool test_scmul3_amd64x() {
    if (impl == NULL) {
        return false;
    }
    assert(check_scmul(rfc7748_alice_priv, test_pt3, rfc7748_alice_pub));
    return true;
}

static bool test_scmul4_amd64x() {
    if (impl == NULL) {
        return false;
    }
    assert(check_scmul(test_sc4, test_pt4, test_re4));
    return true;
}

static bool test_dh_amd64x() {
    if (impl == NULL) {
        return false;
    }
    check_dh();
    return true;
}

int main() {
    RUN_TEST(test_select_auto);
    RUN_TEST(test_select_portable);
    RUN_TEST(test_type_portable);
    RUN_TEST(test_scmul1_portable);
    RUN_TEST(test_scmul2_portable);
    RUN_TEST(test_scmul3_portable);
    RUN_TEST(test_scmul4_portable);
    RUN_TEST(test_dh_portable);
    RUN_TEST(test_invert1);
    RUN_TEST(test_invert2);
    RUN_TEST(test_select_arm64);
    RUN_TEST(test_type_arm64);
    RUN_TEST(test_scmul1_arm64);
    RUN_TEST(test_scmul2_arm64);
    RUN_TEST(test_scmul3_arm64);
    RUN_TEST(test_scmul4_arm64);
    RUN_TEST(test_dh_arm64);
    RUN_TEST(test_select_amd64);
    RUN_TEST(test_type_amd64);
    RUN_TEST(test_scmul1_amd64);
    RUN_TEST(test_scmul2_amd64);
    RUN_TEST(test_scmul3_amd64);
    RUN_TEST(test_scmul4_amd64);
    RUN_TEST(test_dh_amd64);
    RUN_TEST(test_select_amd64x);
    RUN_TEST(test_type_amd64x);
    RUN_TEST(test_scmul1_amd64x);
    RUN_TEST(test_scmul2_amd64x);
    RUN_TEST(test_scmul3_amd64x);
    RUN_TEST(test_scmul4_amd64x);
    RUN_TEST(test_dh_amd64x);

    printf("\nAll tests were successful\n");
    return 0;
}
