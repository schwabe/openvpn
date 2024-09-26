/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2016-2021 Fox Crypto B.V. <openvpn@foxcrypto.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

#include "crypto.h"
#include "crypto_epoch.h"
#include "options.h"
#include "ssl_backend.h"

#include "mss.h"
#include "test_common.h"

static const char testtext[] = "Dummy text to test PEM encoding";

static void
crypto_pem_encode_decode_loopback(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer src_buf;
    buf_set_read(&src_buf, (void *)testtext, sizeof(testtext));

    uint8_t dec[sizeof(testtext)];
    struct buffer dec_buf;
    buf_set_write(&dec_buf, dec, sizeof(dec));

    struct buffer pem_buf;

    assert_true(crypto_pem_encode("TESTKEYNAME", &pem_buf, &src_buf, &gc));
    assert_true(BLEN(&src_buf) < BLEN(&pem_buf));

    /* Wrong key name */
    assert_false(crypto_pem_decode("WRONGNAME", &dec_buf, &pem_buf));

    assert_true(crypto_pem_decode("TESTKEYNAME", &dec_buf, &pem_buf));
    assert_int_equal(BLEN(&src_buf), BLEN(&dec_buf));
    assert_memory_equal(BPTR(&src_buf), BPTR(&dec_buf), BLEN(&src_buf));

    gc_free(&gc);
}

static void
test_translate_cipher(const char *ciphername, const char *openvpn_name)
{
    bool cipher = cipher_valid(ciphername);

    /* Empty cipher is fine */
    if (!cipher)
    {
        return;
    }

    const char *kt_name = cipher_kt_name(ciphername);

    assert_string_equal(kt_name, openvpn_name);
}

static void
test_cipher_names(const char *ciphername, const char *openvpn_name)
{
    struct gc_arena gc = gc_new();
    /* Go through some variants, if the cipher library accepts these, they
     * should be normalised to the openvpn name */
    char *upper = string_alloc(ciphername, &gc);
    char *lower = string_alloc(ciphername, &gc);
    char *random_case = string_alloc(ciphername, &gc);

    for (int i = 0; i < strlen(ciphername); i++)
    {
        upper[i] = (char)toupper((unsigned char)ciphername[i]);
        lower[i] = (char)tolower((unsigned char)ciphername[i]);
        if (rand() & 0x1)
        {
            random_case[i] = upper[i];
        }
        else
        {
            random_case[i] = lower[i];
        }
    }

    if (!openvpn_name)
    {
        openvpn_name = upper;
    }

    test_translate_cipher(upper, openvpn_name);
    test_translate_cipher(lower, openvpn_name);
    test_translate_cipher(random_case, openvpn_name);
    test_translate_cipher(ciphername, openvpn_name);


    gc_free(&gc);
}

static void
crypto_translate_cipher_names(void **state)
{
    /* Test that a number of ciphers to see that they turn out correctly */
    test_cipher_names("BF-CBC", NULL);
    test_cipher_names("BLOWFISH-CBC", "BF-CBC");
    test_cipher_names("Chacha20-Poly1305", NULL);
    test_cipher_names("AES-128-GCM", NULL);
    test_cipher_names("AES-128-CBC", NULL);
    test_cipher_names("CAMELLIA-128-CFB128", "CAMELLIA-128-CFB");
    test_cipher_names("id-aes256-GCM", "AES-256-GCM");
}


static const char *ipsumlorem = "Lorem ipsum dolor sit amet, consectetur "
                                "adipisici elit, sed eiusmod tempor incidunt "
                                "ut labore et dolore magna aliqua.";

static void
crypto_test_tls_prf(void **state)
{
    const char *seedstr = "Quis aute iure reprehenderit in voluptate "
                          "velit esse cillum dolore";
    const unsigned char *seed = (const unsigned char *)seedstr;
    const size_t seed_len = strlen(seedstr);


    const unsigned char *secret = (const unsigned char *) ipsumlorem;
    size_t secret_len = strlen((const char *)secret);


    uint8_t out[32];
    bool ret = ssl_tls1_PRF(seed, (int)seed_len, secret, (int)secret_len, out, sizeof(out));

#if defined(LIBRESSL_VERSION_NUMBER) || defined(ENABLE_CRYPTO_WOLFSSL)
    /* No TLS1 PRF support in these libraries */
    assert_false(ret);
#else
    assert_true(ret);
    uint8_t good_prf[32] = {0xd9, 0x8c, 0x85, 0x18, 0xc8, 0x5e, 0x94, 0x69,
                            0x27, 0x91, 0x6a, 0xcf, 0xc2, 0xd5, 0x92, 0xfb,
                            0xb1, 0x56, 0x7e, 0x4b, 0x4b, 0x14, 0x59, 0xe6,
                            0xa9, 0x04, 0xac, 0x2d, 0xda, 0xb7, 0x2d, 0x67};
    assert_memory_equal(good_prf, out, sizeof(out));
#endif
}

static uint8_t testkey[20] = {0x0b, 0x00};
static uint8_t goodhash[20] = {0x58, 0xea, 0x5a, 0xf0, 0x42, 0x94, 0xe9, 0x17,
                               0xed, 0x84, 0xb9, 0xf0, 0x83, 0x30, 0x23, 0xae,
                               0x8b, 0xa7, 0x7e, 0xb8};

static void
crypto_test_hmac(void **state)
{
    hmac_ctx_t *hmac = hmac_ctx_new();

    assert_int_equal(md_kt_size("SHA1"), 20);

    uint8_t key[20];
    memcpy(key, testkey, sizeof(key));

    hmac_ctx_init(hmac, key, "SHA1");
    hmac_ctx_update(hmac, (const uint8_t *)ipsumlorem, (int) strlen(ipsumlorem));
    hmac_ctx_update(hmac, (const uint8_t *)ipsumlorem, (int) strlen(ipsumlorem));

    uint8_t hash[20];
    hmac_ctx_final(hmac, hash);

    assert_memory_equal(hash, goodhash, sizeof(hash));
    memset(hash, 0x00, sizeof(hash));

    /* try again */
    hmac_ctx_reset(hmac);
    hmac_ctx_update(hmac, (const uint8_t *)ipsumlorem, (int) strlen(ipsumlorem));
    hmac_ctx_update(hmac, (const uint8_t *)ipsumlorem, (int) strlen(ipsumlorem));
    hmac_ctx_final(hmac, hash);

    assert_memory_equal(hash, goodhash, sizeof(hash));

    /* Fill our key with random data to ensure it is not used by hmac anymore */
    memset(key, 0x55, sizeof(key));

    hmac_ctx_reset(hmac);
    hmac_ctx_update(hmac, (const uint8_t *)ipsumlorem, (int) strlen(ipsumlorem));
    hmac_ctx_update(hmac, (const uint8_t *)ipsumlorem, (int) strlen(ipsumlorem));
    hmac_ctx_final(hmac, hash);

    assert_memory_equal(hash, goodhash, sizeof(hash));
    hmac_ctx_cleanup(hmac);
    hmac_ctx_free(hmac);
}

/* This test is in test_crypto as it calls into the functions that calculate
 * the crypto overhead */
static void
test_occ_mtu_calculation(void **state)
{
    struct gc_arena gc = gc_new();

    struct frame f = { 0 };
    struct options o = { 0 };
    size_t linkmtu;

    /* common defaults */
    o.ce.tun_mtu = 1400;
    o.ce.proto = PROTO_UDP;

    /* No crypto at all */
    o.ciphername = "none";
    o.authname = "none";
    linkmtu = calc_options_string_link_mtu(&o, &f);
    assert_int_equal(linkmtu, 1400);

    /* Static key OCC examples */
    o.shared_secret_file = "not null";

    /* secret, auth none, cipher none */
    o.ciphername = "none";
    o.authname = "none";
    linkmtu = calc_options_string_link_mtu(&o, &f);
    assert_int_equal(linkmtu, 1408);

    /* secret, cipher AES-128-CBC, auth none */
    o.ciphername = "AES-128-CBC";
    o.authname = "none";
    linkmtu = calc_options_string_link_mtu(&o, &f);
    assert_int_equal(linkmtu, 1440);

    /* secret, cipher none, auth SHA256 */
    o.ciphername = "none";
    o.authname = "SHA256";
    linkmtu = calc_options_string_link_mtu(&o, &f);
    assert_int_equal(linkmtu, 1440);

    /* secret, cipher BF-CBC, auth SHA1 */
    o.ciphername = "BF-CBC";
    o.authname = "SHA1";
    linkmtu = calc_options_string_link_mtu(&o, &f);
    assert_int_equal(linkmtu, 1444);

    /* secret, cipher BF-CBC, auth SHA1, tcp-client */
    o.ce.proto = PROTO_TCP_CLIENT;
    linkmtu = calc_options_string_link_mtu(&o, &f);
    assert_int_equal(linkmtu, 1446);

    o.ce.proto = PROTO_UDP;

#if defined(USE_COMP)
    o.comp.alg = COMP_ALG_LZO;

    /* secret, comp-lzo yes, cipher BF-CBC, auth SHA1 */
    linkmtu = calc_options_string_link_mtu(&o, &f);
    assert_int_equal(linkmtu, 1445);

#if defined(ENABLE_FRAGMENT)
    /* secret, comp-lzo yes, cipher BF-CBC, auth SHA1, fragment 1200 */
    o.ce.fragment = 1200;
    linkmtu = calc_options_string_link_mtu(&o, &f);
    assert_int_equal(linkmtu, 1449);
    o.ce.fragment = 0;
#endif

    o.comp.alg = COMP_ALG_UNDEF;
#endif

    /* TLS mode */
    o.shared_secret_file = NULL;
    o.tls_client = true;
    o.pull = true;

    /* tls client, cipher AES-128-CBC, auth SHA1, tls-auth */
    o.authname = "SHA1";
    o.ciphername = "AES-128-CBC";
    o.tls_auth_file = "dummy";

    linkmtu = calc_options_string_link_mtu(&o, &f);
    assert_int_equal(linkmtu, 1457);

    /* tls client, cipher AES-128-CBC, auth SHA1 */
    o.tls_auth_file = NULL;

    linkmtu = calc_options_string_link_mtu(&o, &f);
    assert_int_equal(linkmtu, 1457);

    /* tls client, cipher none, auth none */
    o.authname = "none";
    o.ciphername = "none";

    linkmtu = calc_options_string_link_mtu(&o, &f);
    assert_int_equal(linkmtu, 1405);

    /* tls client, auth SHA1, cipher AES-256-GCM */
    o.authname = "SHA1";
    o.ciphername = "AES-256-GCM";
    linkmtu = calc_options_string_link_mtu(&o, &f);
    assert_int_equal(linkmtu, 1449);


#if defined(USE_COMP) && defined(ENABLE_FRAGMENT)
    o.comp.alg = COMP_ALG_LZO;

    /* tls client, auth SHA1, cipher AES-256-GCM, fragment, comp-lzo yes */
    o.ce.fragment = 1200;
    linkmtu = calc_options_string_link_mtu(&o, &f);
    assert_int_equal(linkmtu, 1454);

    /* tls client, auth SHA1, cipher AES-256-GCM, fragment, comp-lzo yes, socks */
    o.ce.socks_proxy_server = "socks.example.com";
    linkmtu = calc_options_string_link_mtu(&o, &f);
    assert_int_equal(linkmtu, 1464);
#endif

    gc_free(&gc);
}

static void
test_mssfix_mtu_calculation(void **state)
{
    struct gc_arena gc = gc_new();

    struct frame f = { 0 };
    struct options o = { 0 };

    /* common defaults */
    o.ce.tun_mtu = 1400;
    o.ce.mssfix = 1000;
    o.ce.proto = PROTO_UDP;

    /* No crypto at all */
    o.ciphername = "none";
    o.authname = "none";
    struct key_type kt;
    init_key_type(&kt, o.ciphername, o.authname, false, false);

    /* No encryption, just packet id (8) + TCP payload(20) + IP payload(20) */
    frame_calculate_dynamic(&f, &kt, &o, NULL);
    assert_int_equal(f.mss_fix, 952);

    /* Static key OCC examples */
    o.shared_secret_file = "not null";

    /* secret, auth none, cipher none */
    o.ciphername = "none";
    o.authname = "none";
    init_key_type(&kt, o.ciphername, o.authname, false, false);
    frame_calculate_dynamic(&f, &kt, &o, NULL);
    assert_int_equal(f.mss_fix, 952);

    /* secret, cipher AES-128-CBC, auth none */
    o.ciphername = "AES-128-CBC";
    o.authname = "none";
    init_key_type(&kt, o.ciphername, o.authname, false, false);

    for (int i = 990; i <= 1010; i++)
    {
        /* 992 - 1008 should end up with the same mssfix value all they
         * all result in the same CBC block size/padding and <= 991 and >=1008
         * should be one block less and more respectively */
        o.ce.mssfix = i;
        frame_calculate_dynamic(&f, &kt, &o, NULL);
        if (i <= 991)
        {
            assert_int_equal(f.mss_fix, 911);
        }
        else if (i >= 1008)
        {
            assert_int_equal(f.mss_fix, 943);
        }
        else
        {
            assert_int_equal(f.mss_fix, 927);
        }
    }
#ifdef USE_COMP
    o.comp.alg = COMP_ALG_LZO;

    /* Same but with compression added. Compression adds one byte extra to the
     * payload so the payload should be reduced by compared to the no
     * compression calculation before */
    for (int i = 990; i <= 1010; i++)
    {
        /* 992 - 1008 should end up with the same mssfix value all they
         * all result in the same CBC block size/padding and <= 991 and >=1008
         * should be one block less and more respectively */
        o.ce.mssfix = i;
        frame_calculate_dynamic(&f, &kt, &o, NULL);
        if (i <= 991)
        {
            assert_int_equal(f.mss_fix, 910);
        }
        else if (i >= 1008)
        {
            assert_int_equal(f.mss_fix, 942);
        }
        else
        {
            assert_int_equal(f.mss_fix, 926);
        }
    }
    o.comp.alg = COMP_ALG_UNDEF;
#endif /* ifdef USE_COMP */

    /* tls client, auth SHA1, cipher AES-256-GCM */
    o.authname = "SHA1";
    o.ciphername = "AES-256-GCM";
    o.tls_client = true;
    o.peer_id = 77;
    o.use_peer_id = true;
    init_key_type(&kt, o.ciphername, o.authname, true, false);

    for (int i = 900; i <= 1200; i++)
    {
        /* For stream ciphers, the value should not be influenced by block
         * sizes or similar but always have the same difference */
        o.ce.mssfix = i;
        frame_calculate_dynamic(&f, &kt, &o, NULL);

        /* 4 byte opcode/peerid, 4 byte pkt ID, 16 byte tag, 40 TCP+IP */
        assert_int_equal(f.mss_fix, i - 4 - 4 - 16 - 40);
    }

    gc_free(&gc);
}

void
crypto_test_aead_limits(void **state)
{
    /* if ChaCha20-Poly1305 is not supported by the crypto library or in the
     * current mode (FIPS), this will still return -1 */
    assert_int_equal(cipher_get_aead_limits("CHACHA20-POLY1305"), 0);

    int64_t aeslimit = cipher_get_aead_limits("AES-128-GCM");

    assert_int_equal(aeslimit, (1ull << 36) - 1);

    /* Check if this matches our exception for 1600 size packets */
    int64_t L = 101;
    /* 2 ^ 29.34, using the result here to avoid linking to libm */
    assert_int_equal(aeslimit / L, 680390858);

    /* and for 9000, 2^26.86 */
    L = 563;
    assert_int_equal(aeslimit / L, 122059461);
}

void
crypto_test_hkdf_expand_testa1(void **state)
{
    /* RFC 5889 A.1 Test Case 1 */
    uint8_t prk[32] =
    {0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
     0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
     0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
     0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5};

    uint8_t info[10] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5,
                        0xf6, 0xf7, 0xf8, 0xf9};

    uint8_t okm[42] =
    {0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
     0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
     0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
     0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
     0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
     0x58, 0x65};

    uint8_t out[42];
    ovpn_hdkf_expand(prk, info, sizeof(info), out, sizeof(out));

    assert_memory_equal(out, okm, sizeof(out));
}

void
crypto_test_hkdf_expand_testa2(void **state)
{
    /* RFC 5889 A.2 Test Case 2 */
    uint8_t prk[32] =
    {0x06, 0xa6, 0xb8, 0x8c, 0x58, 0x53, 0x36, 0x1a,
     0x06, 0x10, 0x4c, 0x9c, 0xeb, 0x35, 0xb4, 0x5c,
     0xef, 0x76, 0x00, 0x14, 0x90, 0x46, 0x71, 0x01,
     0x4a, 0x19, 0x3f, 0x40, 0xc1, 0x5f, 0xc2, 0x44};

    uint8_t info[80] =
    {0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
     0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
     0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
     0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
     0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
     0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
     0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
     0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
     0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
     0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};

    const int L = 82;
    uint8_t okm[82] =
    {0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1,
     0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a, 0x49, 0x34,
     0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8,
     0xa0, 0x50, 0xcc, 0x4c, 0x19, 0xaf, 0xa9, 0x7c,
     0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72,
     0x71, 0xcb, 0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09,
     0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8,
     0x36, 0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71,
     0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec, 0x3e, 0x87,
     0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f,
     0x1d, 0x87};

    uint8_t out[82] = {0xaa};
    ovpn_hdkf_expand(prk, info, sizeof(info), out, L);

    assert_memory_equal(out, okm, L);
}

void
crypto_test_hkdf_expand_testa3(void **state)
{
    /* RFC 5889 A.3 Test Case 3 */
    uint8_t prk[32] =
    {0x19, 0xef, 0x24, 0xa3, 0x2c, 0x71, 0x7b, 0x16,
     0x7f, 0x33, 0xa9, 0x1d, 0x6f, 0x64, 0x8b, 0xdf,
     0x96, 0x59, 0x67, 0x76, 0xaf, 0xdb, 0x63, 0x77,
     0xac, 0x43, 0x4c, 0x1c, 0x29, 0x3c, 0xcb, 0x04};

    uint8_t info[0] = {};

    int L = 42;
    uint8_t okm[42] =
    {0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f,
     0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c, 0x5a, 0x31,
     0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e,
     0xc3, 0x45, 0x4e, 0x5f, 0x3c, 0x73, 0x8d, 0x2d,
     0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a,
     0x96, 0xc8};

    uint8_t out[42];
    ovpn_hdkf_expand(prk, info, sizeof(info), out, L);

    assert_memory_equal(out, okm, L);
}

int
main(void)
{
    openvpn_unit_test_setup();
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(crypto_pem_encode_decode_loopback),
        cmocka_unit_test(crypto_translate_cipher_names),
        cmocka_unit_test(crypto_test_tls_prf),
        cmocka_unit_test(crypto_test_hmac),
        cmocka_unit_test(test_occ_mtu_calculation),
        cmocka_unit_test(test_mssfix_mtu_calculation),
        cmocka_unit_test(crypto_test_aead_limits),
        cmocka_unit_test(crypto_test_hkdf_expand_testa1),
        cmocka_unit_test(crypto_test_hkdf_expand_testa2),
        cmocka_unit_test(crypto_test_hkdf_expand_testa3)
    };

#if defined(ENABLE_CRYPTO_OPENSSL)
    OpenSSL_add_all_algorithms();
#endif

    int ret = cmocka_run_group_tests_name("crypto tests", tests, NULL, NULL);

#if defined(ENABLE_CRYPTO_OPENSSL)
    EVP_cleanup();
#endif

    return ret;
}
