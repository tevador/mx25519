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
    fflush(stdout);
    printf(func() ? "PASSED\n" : "SKIPPED\n");
}

typedef void clamp_func(mx25519_privkey* key);

static void torsion_clamping(mx25519_privkey* key) {
    key->data[0] &= 248;
}

static void rfc7748_clamping(mx25519_privkey* key) {
    key->data[0] &= 248;
    key->data[31] &= 127;
    key->data[31] |= 64;
}

typedef struct scmul_vector {
    const char* scalar;
    const char* point;
    const char* result;
    clamp_func* clamping;
} scmul_vector;

static const char rfc7748_sc1[] = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4";

static const scmul_vector scmul_vectors[] = {
    /* 0: first RFC 7748 test vector */
    {
        .scalar = rfc7748_sc1,
        .point = "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        .result = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        .clamping = &rfc7748_clamping
    },

    /* 1: second RFC 7748 test vector */
    {
        .scalar = "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
        .point = "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
        .result = "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
        .clamping = &rfc7748_clamping
    },

    /* 2: base point > 2^255-19 */
    {
        .scalar = "a92b2c3964e188a899d6f74b99679013b0a2510b5a6a0a90739e444b23f7bae6",
        .point = "f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        .result = "18b1569101d55e0e7e8527a73e27d43393a2d4ec73e67078064bc2a56dcb5860",
        .clamping = &rfc7748_clamping
    },

    /* 3: scalar with bit 254 clear and bit 255 set */
    {
        .scalar = "abc58a54782e87c7052458c2caa461aa27024fb08801ad4bb376b880e449da88",
        .point = "08558f428dff0dc8ee4bebf2408982cf65538a3ae57dffe4f49f43f5506ccd09",
        .result = "cd178e864e4f3dd3f5e945c04b87825b84d8a224b6c240784515c5f87af27647",
        .clamping = &torsion_clamping
    },

    /* 4: scalar 1, point 2^205+2^153, AMD64X adox carry in X3^2 */
    {
        .scalar = "0100000000000000000000000000000000000000000000000000000000000000",
        .point = "0000000000000000000000000000000000000002000000000020000000000000",
        .result = "0000000000000000000000000000000000000002000000000020000000000000"
    },

    /* 5: scalar 1, Z2 = 2^255+1 entering the inversion */
    {
        .scalar = "0100000000000000000000000000000000000000000000000000000000000000",
        .point = "6c56d74c736542c73630387cad9331f4f7454273c977bc27b5df0e497463451a",
        .result = "6c56d74c736542c73630387cad9331f4f7454273c977bc27b5df0e497463451a"
    },

    /* 6: scalar 1, first AMD64 inversion squaring overflows propagating carries */
    {
        .scalar = "0100000000000000000000000000000000000000000000000000000000000000",
        .point = "8f5af1108df7369660d6f068aa9211c9762522fa40d5dba6f94943ab64d3b66b",
        .result = "8f5af1108df7369660d6f068aa9211c9762522fa40d5dba6f94943ab64d3b66b"
    },

    /* 7: scalar 1, second AMD64 inversion product is 2^255+1 */
    {
        .scalar = "0100000000000000000000000000000000000000000000000000000000000000",
        .point = "356abee0fdea9fd3a30e3de8844bfb4bc5d9ea808e9cbe11d27269032cb3943a",
        .result = "356abee0fdea9fd3a30e3de8844bfb4bc5d9ea808e9cbe11d27269032cb3943a"
    },

    /* 8: scalar 1, Z2 needs 558 divsteps */
    {
        .scalar = "0100000000000000000000000000000000000000000000000000000000000000",
        .point = "0d17852d429cd3f1353559c2221cea391d3a98dd15064787bc56c5600f4f7457",
        .result = "0d17852d429cd3f1353559c2221cea391d3a98dd15064787bc56c5600f4f7457"
    },

    /* 9: scalar 1, Z2 needs over 600 plain divsteps */
    {
        .scalar = "0100000000000000000000000000000000000000000000000000000000000000",
        .point = "a5cdcf951bc1b54ae8e42d8b14ad25e9db85a0faeb8e990e9b94e471cc7e887b",
        .result = "a5cdcf951bc1b54ae8e42d8b14ad25e9db85a0faeb8e990e9b94e471cc7e887b"
    },

    /* 10: scalar 1, Z2 needs 555 divsteps, last update carries in every limb */
    {
        .scalar = "0100000000000000000000000000000000000000000000000000000000000000",
        .point = "25bcba8a72a3f3f4ce1ec1e72e7184106b664744c045dd9eff50b6dd7ca8a909",
        .result = "25bcba8a72a3f3f4ce1ec1e72e7184106b664744c045dd9eff50b6dd7ca8a909"
    },

    /* 11: scalar 1, inversion result 2^255-2^64-2, its second fold borrows */
    {
        .scalar = "0100000000000000000000000000000000000000000000000000000000000000",
        .point = "41a167e705e0208ba9d914441190d8f3b3824326bece65a19aa68e2b6d252c3c",
        .result = "41a167e705e0208ba9d914441190d8f3b3824326bece65a19aa68e2b6d252c3c"
    },

    /* 12: scalar 1, point 20, 2^255+1 before the final reduction */
    {
        .scalar = "0100000000000000000000000000000000000000000000000000000000000000",
        .point = "1400000000000000000000000000000000000000000000000000000000000000",
        .result = "1400000000000000000000000000000000000000000000000000000000000000"
    },

    /* 13: scalar 2, point 2^255-35, Z2 = T3 * T4 fold carries into its top limb */
    {
        .scalar = "0200000000000000000000000000000000000000000000000000000000000000",
        .point = "ddffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        .result = "cf1b0c47e22b394a3aae005c7718160d29a91326e85a85cd1306edada4f1e65f"
    },

    /* 14: scalar 2, point 2^255-21, ARM64 carries packing Z2 into 64-bit limbs */
    {
        .scalar = "0200000000000000000000000000000000000000000000000000000000000000",
        .point = "ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        .result = "f8e8cba87148bac5c66a0768491ddd03f2f4e106f8c543ec9533b20f45551637"
    },

    /* 15: scalar 2, point 2^255-20 of order 4, output 0 must not come out as p */
    {
        .scalar = "0200000000000000000000000000000000000000000000000000000000000000",
        .point = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        .result = "0000000000000000000000000000000000000000000000000000000000000000"
    },

    /* 16: scalar 5, point 2^255-83, AMD64 carry in X3 = T1 * T4 */
    {
        .scalar = "0500000000000000000000000000000000000000000000000000000000000000",
        .point = "adffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        .result = "1a1120bff585af8ac38b0dd6edff55adc81a663d98ef13bd66c304a20eeb2a7c"
    },

    /* 17: scalar 5, point 2^255-31, AMD64 carries in Z3 = T2 * T3 and T1^2 */
    {
        .scalar = "0500000000000000000000000000000000000000000000000000000000000000",
        .point = "e1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        .result = "f15016c7df7d85ba1e6fcb0bbc1707034f790058e1de3a6f46f31b2ddabd8325"
    },

    /* 18: scalar 33, point 2^255-83, AMD64X adox carry in X3 = T1 * T4 */
    {
        .scalar = "2100000000000000000000000000000000000000000000000000000000000000",
        .point = "adffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        .result = "55aa271c1c6aa5020f717ebd4c237672479de57c705501b8695ad10b1627ed37"
    },

    /* 19: first RFC 7748 scalar, point 2, AMD64 carry in X3 = T1 * T4 */
    {
        .scalar = rfc7748_sc1,
        .point = "0200000000000000000000000000000000000000000000000000000000000000",
        .result = "71cacba0b65daf53ddf9c21fb434bc58ee5cfa3954d1b642fc5155048f03466f",
        .clamping = &rfc7748_clamping
    },

    /* 20: first RFC 7748 scalar, point 2^127, carries in X2 = T1 * T2 */
    {
        .scalar = rfc7748_sc1,
        .point = "0000000000000000000000000000008000000000000000000000000000000000",
        .result = "ff4c6f9e545c8e8d04f290a2211f0e06d16e6517b564353dc25596ad42094351",
        .clamping = &rfc7748_clamping
    },

    /* 21: first RFC 7748 scalar, point 2^255-2^224-15, rare ladder-step carries */
    {
        .scalar = rfc7748_sc1,
        .point = "f1fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffff7f",
        .result = "16c082873321599c65e52cf2b0046f21acc1b9bcaa275ef17d760b6ddd42ae7d",
        .clamping = &rfc7748_clamping
    },

    /* 22: first RFC 7748 scalar, point 2^255-24, AMD64 carry in Z3 = T2 * T3 */
    {
        .scalar = rfc7748_sc1,
        .point = "e8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        .result = "09b692ccedf8f926cf7798a0a81969f05a9e644640c570eb72fb1b9427cc2774",
        .clamping = &rfc7748_clamping
    },

    /* 23: first RFC 7748 scalar, 121666 * T3 carries through every 64-bit limb */
    {
        .scalar = rfc7748_sc1,
        .point = "f1ffffffffffffff67720e37c5f042dd67720e37c5f042dd67720e37c5f0427d",
        .result = "e5e16772c8145dd28617c3524e670eeb8a043afc469982c25e03eb775fbc6e2d",
        .clamping = &rfc7748_clamping
    },

    /* 24: first RFC 7748 scalar, X2 - Z2 = 1-2^192 at the second ladder step */
    {
        .scalar = rfc7748_sc1,
        .point = "73945343845cc6be2833f18e1029759ea70451a3bc35c53fd18a39ff3d42b206",
        .result = "4acccdf15f8352b860c5af99b3ffd8beb8b7b1432588165af9e957be211e2c70",
        .clamping = &rfc7748_clamping
    },

    /* 25: scalar found by search, point 2^63, AMD64X adox carry in T2^2 */
    {
        .scalar = "06dbe0d4ea2d68373fe4ed454abce4c98a5c1a94f8b3bd07b9b2edb96806217c",
        .point = "0000000000000080000000000000000000000000000000000000000000000000",
        .result = "587ba9a9ff569a97861051fd0ec7cd2f6f03dc9275811822183f7cc984513d69"
    },

    /* 26: scalar found by search, point 2^102-2^5, AMD64X adox carry in T2^2 */
    {
        .scalar = "be3410d02b559f8663a3f065350c8c7f7c4e7b82a25717571f45b69d6daef330",
        .point = "e0ffffffffffffffffffffff3f00000000000000000000000000000000000000",
        .result = "d2c2c0389efad12edcf9e98dfa4d358c7e27a919b27d9d16901bb0fcad608565"
    },

    /* 27: scalar found by search, point 2^175-2^67, AMD64X adox carry in T1^2 */
    {
        .scalar = "99bd9e48929e35696cea36d8b97f1c2f2820948899b57587c4d35cd8d3ad9554",
        .point = "0000000000000000f8ffffffffffffffffffffffff7f00000000000000000000",
        .result = "1d9da9acf568565f82d25f076881feff5807568d417b8295a971ba9e17b0c268"
    },

    /* 28: scalar found by search, point 2^228-2^20, AMD64X adox carries in Z2 = T3 * T4 */
    {
        .scalar = "085a360376eff2652fcd97e47879efc4c3626aa546b9438308f7336ff8bea857",
        .point = "0000f0ffffffffffffffffffffffffffffffffffffffffffffffffff0f000000",
        .result = "2d692d853ed023798be0987dd9e96e4c105e0489600edfb82b0154b7d00f6d5c"
    },

    /* 29: scalar found by search, point 2^255-2^127, AMD64X top adox carries */
    {
        .scalar = "f81f790f0b1affd9d94971c387f88643c25b7ab6fd6d6f0c295dcf14334b3e53",
        .point = "00000000000000000000000000000080ffffffffffffffffffffffffffffff7f",
        .result = "9a33e74a6a085eb1b4cf7d114391ec750428453caf37ac72fe2aafc4b600fe6f"
    }
};

/* DH key exchange tests */
static const char rfc7748_alice_priv[] = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
static const char rfc7748_alice_pub[] = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
static const char rfc7748_bob_priv[] = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
static const char rfc7748_bob_pub[] = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
static const char rfc7748_shared[] = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

static const mx25519_impl* impl;

static char parse_nibble(char hex) {
    hex &= ~0x20;
    return (hex & 0x40) ? hex - ('A' - 10) : hex & 0xf;
}

static void hex2bin(const char* in, int length, uint8_t* out) {
    for (int i = 0; i < length; i += 2) {
        char nibble1 = parse_nibble(*in++);
        char nibble2 = parse_nibble(*in++);
        *out++ = (uint8_t)nibble1 << 4 | (uint8_t)nibble2;
    }
}

#define KEY_SIZE 32

static void load_privkey(mx25519_privkey* key, const char* hex, clamp_func* clamping) {
    hex2bin(hex, 2 * KEY_SIZE, key->data);
    if (clamping != NULL) {
        clamping(key);
    }
}

static void load_pubkey(mx25519_pubkey* pubkey, const char* hex) {
    hex2bin(hex, 2 * KEY_SIZE, pubkey->data);
}

static bool equals_hex(const void* val, const char* hex) {
    uint8_t reference[KEY_SIZE];
    hex2bin(hex, 2 * KEY_SIZE, reference);
    return memcmp(val, reference, sizeof(reference)) == 0;
}

static void print_hex(const char* label, const uint8_t* data) {
    fprintf(stderr, " %s ", label);
    for (int i = 0; i < KEY_SIZE; ++i) {
        fprintf(stderr, "%02x", data[i]);
    }
}

static bool check_scmul_case(
    const char* label,
    const mx25519_privkey* key,
    const mx25519_pubkey* pt,
    const mx25519_pubkey* expected
) {
    mx25519_pubkey res;
    memset(&res, 0xff, sizeof(res));
    mx25519_scmul_key_unclamped(impl, &res, key, pt);
    if (memcmp(res.data, expected->data, KEY_SIZE) == 0) {
        return true;
    }
    fprintf(stderr, "\n%s failed:", label);
    print_hex("scalar", key->data);
    print_hex("point", pt->data);
    print_hex("expected", expected->data);
    print_hex("got", res.data);
    fprintf(stderr, "\n");
    return false;
}

static void check_scmul_vectors() {
    assert(impl != NULL);
    for (size_t i = 0; i < sizeof(scmul_vectors) / sizeof(scmul_vectors[0]); ++i) {
        const scmul_vector* v = &scmul_vectors[i];
        char label[32];
        snprintf(label, sizeof(label), "scmul_vectors[%i]", (int)i);
        mx25519_privkey key;
        load_privkey(&key, v->scalar, v->clamping);
        mx25519_pubkey pt;
        load_pubkey(&pt, v->point);
        mx25519_pubkey expected;
        load_pubkey(&expected, v->result);
        assert(check_scmul_case(label, &key, &pt, &expected));
    }
}

static const char field_p[] = "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";

static void reduce_mod_p(uint8_t* s) {
    uint8_t p[KEY_SIZE];
    hex2bin(field_p, 2 * KEY_SIZE, p);
    while (true) {
        uint8_t d[KEY_SIZE];
        int borrow = 0;
        for (int i = 0; i < KEY_SIZE; ++i) {
            int v = s[i] - p[i] - borrow;
            d[i] = (uint8_t)v;
            borrow = v < 0;
        }
        if (borrow) {
            return;
        }
        memcpy(s, d, KEY_SIZE);
    }
}

static bool check_scalar_one(const uint8_t* u, const char* family, int param) {
    char label[64];
    snprintf(
        label,
        sizeof(label),
        "scalar 1, %s = %i%s",
        family,
        param,
        (u[KEY_SIZE - 1] & 0x80) ? ", bit 255 set" : ""
    );
    const mx25519_privkey one = { .data = {1} };
    mx25519_pubkey pt;
    memcpy(pt.data, u, KEY_SIZE);
    mx25519_pubkey expected = pt;
    expected.data[KEY_SIZE - 1] &= 0x7f;
    reduce_mod_p(expected.data);
    return check_scmul_case(label, &one, &pt, &expected);
}

static void check_field_edges() {
    assert(impl != NULL);
    uint8_t p[KEY_SIZE];
    hex2bin(field_p, 2 * KEY_SIZE, p);
    for (int t = 0; t <= 32; ++t) {
        uint8_t u[KEY_SIZE] = {0};
        u[0] = (uint8_t)t;
        assert(check_scalar_one(u, "u = t, t", t));
        u[KEY_SIZE - 1] |= 0x80;
        assert(check_scalar_one(u, "u = t, t", t));
        memcpy(u, p, KEY_SIZE);
        u[0] -= (uint8_t)t;
        assert(check_scalar_one(u, "u = p-t, t", t));
        u[KEY_SIZE - 1] |= 0x80;
        assert(check_scalar_one(u, "u = p-t, t", t));
        if (t < 19) {
            memcpy(u, p, KEY_SIZE);
            u[0] += (uint8_t)t;
            assert(check_scalar_one(u, "u = p+t, t", t));
            u[KEY_SIZE - 1] |= 0x80;
            assert(check_scalar_one(u, "u = p+t, t", t));
        }
    }
    uint8_t ones[KEY_SIZE] = {0};
    for (int k = 0; k < 255; ++k) {
        uint8_t bit = (uint8_t)(1 << (k % 8));
        uint8_t u[KEY_SIZE] = {0};
        u[k / 8] = bit;
        assert(check_scalar_one(u, "u = 2^k, k", k));
        ones[k / 8] |= bit;
        assert(check_scalar_one(ones, "u = 2^(k+1)-1, k", k));
        memcpy(u, p, KEY_SIZE);
        u[k / 8] -= bit;
        assert(check_scalar_one(u, "u = p-2^k, k", k));
    }
}

typedef uint32_t gf[8];

static void gf_from_bytes(gf r, const uint8_t* s) {
    memset(r, 0, sizeof(gf));
    for (int i = 0; i < KEY_SIZE; ++i) {
        r[i / 4] |= (uint32_t)s[i] << (8 * (i % 4));
    }
}

static void gf_to_bytes(uint8_t* s, const gf a) {
    for (int i = 0; i < KEY_SIZE; ++i) {
        s[i] = (uint8_t)(a[i / 4] >> (8 * (i % 4)));
    }
    reduce_mod_p(s);
}

static void gf_mul(gf r, const gf a, const gf b) {
    uint64_t t[16] = {0};
    for (int i = 0; i < 8; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < 8; ++j) {
            carry += t[i + j] + (uint64_t)a[i] * b[j];
            t[i + j] = (uint32_t)carry;
            carry >>= 32;
        }
        t[i + 8] = carry;
    }
    uint64_t carry = 0;
    for (int i = 0; i < 8; ++i) {
        carry += t[i] + 38 * t[i + 8];
        r[i] = (uint32_t)carry;
        carry >>= 32;
    }
    while (carry != 0) {
        carry *= 38;
        for (int i = 0; i < 8; ++i) {
            carry += r[i];
            r[i] = (uint32_t)carry;
            carry >>= 32;
        }
    }
}

static void gf_pow(gf r, const gf a, const uint8_t* e) {
    gf x;
    memcpy(x, a, sizeof(gf));
    memset(r, 0, sizeof(gf));
    r[0] = 1;
    for (int i = 8 * KEY_SIZE - 1; i >= 0; --i) {
        gf_mul(r, r, r);
        if ((e[i / 8] >> (i % 8)) & 1) {
            gf_mul(r, r, x);
        }
    }
}

static const char root19[] = "3b790de53594d7505e43790de53594d7505e43790de53594d7505e43790de535";

/*
 * With scalar 1 the ladder hands Z2 = (4u)^19 to the inversion, so the point
 * u = z^(1/19) / 4 makes the inversion see z.
 */
static void check_inversion_edges() {
    assert(impl != NULL);
    uint8_t p[KEY_SIZE];
    hex2bin(field_p, 2 * KEY_SIZE, p);
    uint8_t p_minus_2[KEY_SIZE];
    memcpy(p_minus_2, p, KEY_SIZE);
    p_minus_2[0] -= 2;
    uint8_t root[KEY_SIZE];
    hex2bin(root19, 2 * KEY_SIZE, root);
    const gf four = {4};
    gf quarter;
    gf_pow(quarter, four, p_minus_2);
    const uint8_t nineteen[KEY_SIZE] = {19};
    static const char* const families[4] = {
        "Z2 = t, t",
        "Z2 = -t, t",
        "Z2 = 1/t, t",
        "Z2 = -1/t, t"
    };
    for (int t = 1; t <= 32; ++t) {
        uint8_t bytes[KEY_SIZE] = {0};
        bytes[0] = (uint8_t)t;
        gf z[4];
        gf_from_bytes(z[0], bytes);
        memcpy(bytes, p, KEY_SIZE);
        bytes[0] -= (uint8_t)t;
        gf_from_bytes(z[1], bytes);
        gf_pow(z[2], z[0], p_minus_2);
        gf_pow(z[3], z[1], p_minus_2);
        for (int i = 0; i < 4; ++i) {
            gf u, check;
            gf_pow(u, z[i], root);
            gf_mul(u, u, quarter);
            gf_mul(check, u, four);
            gf_pow(check, check, nineteen);
            uint8_t lhs[KEY_SIZE], rhs[KEY_SIZE];
            gf_to_bytes(lhs, check);
            gf_to_bytes(rhs, z[i]);
            assert(memcmp(lhs, rhs, KEY_SIZE) == 0);
            uint8_t point[KEY_SIZE];
            gf_to_bytes(point, u);
            assert(check_scalar_one(point, families[i], t));
        }
    }
}

static void check_scmul() {
    check_scmul_vectors();
    check_field_edges();
    check_inversion_edges();
}

static void check_dh() {
    assert(impl != NULL);
    mx25519_privkey alice_priv, bob_priv;
    load_privkey(&alice_priv, rfc7748_alice_priv, &rfc7748_clamping);
    load_privkey(&bob_priv, rfc7748_bob_priv, &rfc7748_clamping);
    mx25519_pubkey alice_pub, bob_pub;
    mx25519_scmul_base_unclamped(impl, &alice_pub, &alice_priv);
    assert(equals_hex(&alice_pub, rfc7748_alice_pub));
    mx25519_scmul_base_unclamped(impl, &bob_pub, &bob_priv);
    assert(equals_hex(&bob_pub, rfc7748_bob_pub));
    mx25519_pubkey alice_shared, bob_shared;
    mx25519_scmul_key_unclamped(impl, &alice_shared, &alice_priv, &bob_pub);
    assert(equals_hex(&alice_shared, rfc7748_shared));
    mx25519_scmul_key_unclamped(impl, &bob_shared, &bob_priv, &alice_pub);
    assert(equals_hex(&bob_shared, rfc7748_shared));
}

static void check_mul_base_times1() {
    assert(impl != NULL);
    const mx25519_privkey one = { .data = {1} };
    const mx25519_pubkey B = { .data = {9} };
    mx25519_pubkey B1;
    memset(&B1, 0xff, sizeof(B1));
    mx25519_scmul_base_unclamped(impl, &B1, &one);
    assert(memcmp(&B1, &B, sizeof(B)) == 0);
}

static bool test_select_auto() {
    impl = mx25519_select_impl(MX25519_TYPE_AUTO);
    assert(impl != NULL);
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

static bool test_scmul_portable() {
    check_scmul();
    return true;
}

static bool test_dh_portable() {
    check_dh();
    return true;
}

static bool test_mul_base_times1_portable() {
    check_mul_base_times1();
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

static bool test_scmul_arm64() {
    if (impl == NULL) {
        return false;
    }
    check_scmul();
    return true;
}

static bool test_dh_arm64() {
    if (impl == NULL) {
        return false;
    }
    check_dh();
    return true;
}

static bool test_mul_base_times1_arm64() {
    if (impl == NULL) {
        return false;
    }
    check_mul_base_times1();
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

static bool test_scmul_amd64() {
    if (impl == NULL) {
        return false;
    }
    check_scmul();
    return true;
}

static bool test_dh_amd64() {
    if (impl == NULL) {
        return false;
    }
    check_dh();
    return true;
}

static bool test_mul_base_times1_amd64() {
    if (impl == NULL) {
        return false;
    }
    check_mul_base_times1();
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

static bool test_scmul_amd64x() {
    if (impl == NULL) {
        return false;
    }
    check_scmul();
    return true;
}

static bool test_dh_amd64x() {
    if (impl == NULL) {
        return false;
    }
    check_dh();
    return true;
}

static bool test_mul_base_times1_amd64x() {
    if (impl == NULL) {
        return false;
    }
    check_mul_base_times1();
    return true;
}

int main() {
    RUN_TEST(test_select_auto);
    RUN_TEST(test_select_portable);
    RUN_TEST(test_type_portable);
    RUN_TEST(test_scmul_portable);
    RUN_TEST(test_dh_portable);
    RUN_TEST(test_mul_base_times1_portable);
    RUN_TEST(test_select_arm64);
    RUN_TEST(test_type_arm64);
    RUN_TEST(test_scmul_arm64);
    RUN_TEST(test_dh_arm64);
    RUN_TEST(test_mul_base_times1_arm64);
    RUN_TEST(test_select_amd64);
    RUN_TEST(test_type_amd64);
    RUN_TEST(test_scmul_amd64);
    RUN_TEST(test_dh_amd64);
    RUN_TEST(test_mul_base_times1_amd64);
    RUN_TEST(test_select_amd64x);
    RUN_TEST(test_type_amd64x);
    RUN_TEST(test_scmul_amd64x);
    RUN_TEST(test_dh_amd64x);
    RUN_TEST(test_mul_base_times1_amd64x);
    printf("\nAll tests were successful\n");
    return 0;
}
