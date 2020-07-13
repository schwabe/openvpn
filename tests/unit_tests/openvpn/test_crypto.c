/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2016-2018 Fox Crypto B.V. <openvpn@fox-it.com>
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
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

#include "crypto.h"

#include "mock_msg.h"
#include "options.h"

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
    const cipher_kt_t *cipher = cipher_kt_get(ciphername);

    /* Empty cipher is fine */
    if (!cipher)
    {
        return;
    }

    const char *kt_name = cipher_kt_name(cipher);

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
        upper[i] = toupper(ciphername[i]);
        lower[i] = tolower(ciphername[i]);
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


static void
crypto_test_crypt_size_calculation(void **state)
{
    /* This test does not test really much but if this fails
    * the other tests might need to be adjusted as well */
    assert_int_equal(crypto_max_overhead(), 120);

    struct key_type kt_null = {0};

    /* null cipher and auth */
    assert_int_equal(crypto_calc_frame_overhead(&kt_null, false, false), 0);

    init_key_type(&kt_null, "none",  "none", 0,  0, false);
    assert_int_equal(crypto_calc_frame_overhead(&kt_null, false, false), 0);

    /* Short(4) and long(8) packet id */
    assert_int_equal(crypto_calc_frame_overhead(&kt_null, true, false), 4);
    assert_int_equal(crypto_calc_frame_overhead(&kt_null, true, true), 8);


    /* BF CBC,  8 pkt id, 8 iv, 8 block size*/
    struct key_type kt_bfcbc = {0};
    init_key_type(&kt_bfcbc, "bf-cbc",  "none", 0,  0, false);
    assert_int_equal(crypto_calc_frame_overhead(&kt_bfcbc, true, true), 24);

    /* BF CBC,  8 pkt id, 8 iv, 8 block size, 20 byte sha1 */
    struct key_type kt_bfcbcsha1 = {0};
    init_key_type(&kt_bfcbcsha1, "bf-cbc",  "sha1", 0,  0, false);
    assert_int_equal(crypto_calc_frame_overhead(&kt_bfcbcsha1, true, true), 44);

    /* AES 128 CBC+SHA1, 8 pkt id, 16 iv, 16 blocksize, 20 sha1 */
    struct key_type kt_aes_cbc_sha1 = {0};
    init_key_type(&kt_aes_cbc_sha1, "aes-128-cbc",  "sha1", 0,  0, false);
    assert_int_equal(crypto_calc_frame_overhead(&kt_aes_cbc_sha1, true, true), 60);

    /* AES 256 CBC+SHA256 - the more bit are better option as seen in TV
    * 8 pkt id, 16 iv, 16 blocksize, 32 sha256 */
    struct key_type kt_aes_cbc_sha256 = {0};
    init_key_type(&kt_aes_cbc_sha256, "aes-256-cbc",  "sha256", 0,  0, false);
    assert_int_equal(crypto_calc_frame_overhead(&kt_aes_cbc_sha256, true, true), 72);

    /* AES-256-GCM, 8 pkt id, 12 iv, 16 blksize, 16 tag */
    struct key_type kt_aesgcm = {0};
    init_key_type(&kt_aesgcm, "aes-256-gcm",  "none", 0,  true, false);
    assert_int_equal(crypto_calc_frame_overhead(&kt_aesgcm, true, true), 52);
}

static void
frame_calculate_mtu_test(const char *ciphername, const char *auth,
                         int expected_link_mtu)
{
  struct frame f = { 0 };

  struct options o = { 0 };
  o.ciphername = ciphername;
  o.authname = auth;
  o.pull = true;
  o.replay = true;

  o.ce.tun_mtu = 1500;
  o.ce.tun_mtu_defined = true;

  /* Replicate the hack we do to get the right size */
  frame_add_to_extra_frame(&f, crypto_max_overhead());

  int mtu = calc_options_string_link_mtu(&o, &f);
  assert_int_equal(mtu, expected_link_mtu);
}

static void
frame_calculate_mtu(void** state)
{
    frame_calculate_mtu_test("bf-cbc", "sha1", 1540);
    frame_calculate_mtu_test("aes-128-cbc", "sha1", 1556);
    frame_calculate_mtu_test("aes-256-gcm", "sha1", 1548);

    //BF-CBC+SHA1 Data Channel MTU parms [ L:1622 D:1450 EF:122 EB:406 ET:0 EL:3 ]
    //AES-128-GCM Data Channel MTU parms [ L:1553 D:1450 EF:53 EB:406 ET:0 EL:3 ]

    // GCM server Data Channel MTU parms [ L:1550 D:1450 EF:50 EB:406 ET:0 EL:3 ]


    //bf-cbc sha1 Data Channel MTU parms [ L:1542 D:1450 EF:42 EB:406 ET:0 EL:3 ]

    // 56 - 53 = 3
    // 50 - 48 = 2
    // 42 - 40 = 2

    // no compt

    //CBC serv [ L:1541 D:1450 EF:41 EB:406 ET:0 EL:3 ]
    // 656 - 587 = 69

    // 1500 payload with 16 byte blocksize => 1504
    // 1500 payload with 8 byte blocksize => 1504



    // 1280 srv: [ L:1321 D:1321 EF:41 EB:369 ET:0 EL:3 ]
    // 1281 srv: [ L:1322 D:1322 EF:41 EB:369 ET:0 EL:3 ]

    // 1282 srv: [ L:1323 D:1323 EF:41 EB:369 ET:0 EL:3 ]
    // 1283 srv: [ L:1324 D:1324 EF:41 EB:370 ET:0 EL:3 ]


    
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(crypto_pem_encode_decode_loopback),
        cmocka_unit_test(crypto_translate_cipher_names),
        cmocka_unit_test(crypto_test_crypt_size_calculation),
        cmocka_unit_test(frame_calculate_mtu),
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
