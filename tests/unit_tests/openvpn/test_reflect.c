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
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include "bloom.h"
#include "buffer.h"
#include "reflect_filter.h"
#include "test_common.h"

#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>

#include <stdio.h>



static void
test_bloom(void **state)
{
    static const int present_mod = 77;

    struct gc_arena gc = gc_new();
    /* Use a bloom filter with 1M entries (256kB) for the unit test */
    struct bloom_filter *bf = bloom_create(1024ul*1024, 8, &gc);

    for (int32_t i = 0; i < 20000; i += present_mod)
    {
        bloom_add(bf, (const uint8_t *) &i, sizeof(i));
    }

    /* all these should be positive, for the small unit test we do not expect
     * false positive */
    for (int32_t i = 0; i < 20000; i++)
    {
        int present = (i % present_mod == 0 ) ? 1 : 0;
        /* cast to bool to only get 1 and 0 for present/not present and not */
        assert_int_equal((bool) bloom_test(bf, (const uint8_t *) &i, sizeof(i)), present);
    }

    bloom_free(bf);
    gc_free(&gc);
}

static void
test_reflect_ddos(void **state)
{
    /* This tests if the bloom filter implementation does actually work with
     * the goal of dropping packets to a reflected /24 while still allowing
     * other clients */

    /* Disable the normal fallback that puts a hard cap on the reflection filter */
    struct initial_packet_rate_limit *irl = initial_rate_limit_init(INT_MAX, 300, NULL);

    reflect_add_filter_tier(&irl->bloom_conf, &irl->gc, false, 24, 5);
    reflect_add_filter_tier(&irl->bloom_conf, &irl->gc, false, 8, 20);
    init_bloom_filter(irl);

    int num_legimate_reject = 0;
    int num_legimate_accepted = 0;

    int num_ddos_rejected = 0;
    int num_ddos_accepted = 0;


    /* /24 net addresses in host byte order */
    in_addr_t net_attack[4];
    for (int i = 0; i < 3; i++)
    {
        net_attack[i] = random() % 0xff;
    }

    /* The 4th network is close enough to the 3rd to fall in the same /16 */
    /* XOR the 3rd byte to achieve this */
    net_attack[3] = net_attack[2] ^ 00002300;

    /* Assume 200000 packets, including roughly 200 legitimate packets,
     * the unit test works also with 20 millions packet but takes too long*/
    static const int total_packets = 200 * 1000;

    for (int i = 0; i < total_packets; i++)
    {
        struct openvpn_sockaddr from = { 0 };
        from.addr.in4.sin_family = AF_INET;
        from.addr.in4.sin_addr.s_addr = random();
        from.addr.in4.sin_port = random();

        if (i % 1023 == 0)
        {
            /* roughly 200 legitimate clients with random addresses */
            from.addr.in4.sin_addr.s_addr = random();

            bool allowed = reflect_filter_check(irl, &from);
            if (allowed)
            {
                num_legimate_accepted++;
            }
            else
            {
                num_legimate_reject++;
            }

        }
        else
        {
            /* We attack the 4 networks at random */
            from.addr.in4.sin_addr.s_addr  = net_attack[random() % 4] + (random() % 256);

            bool allowed  = reflect_filter_check(irl, &from);
            if (allowed)
            {
                num_ddos_accepted++;
            }
            else
            {
                num_ddos_rejected++;
            }
        }
    }

    assert_int_equal(num_legimate_reject + num_legimate_accepted + num_ddos_accepted + num_ddos_rejected, total_packets);

    /* We assume that most legitimate made it through but a few were unfortunate to be in an attacked network */
    assert_in_range(num_legimate_reject, 0, 10);

    /* We disabled total number of packets, so we expect all /8 to have their
     * 20 packets, which is 5120. */
    assert_in_range(num_ddos_accepted, 0, 256 * 20);

    initial_rate_limit_free(irl);
}


static void
test_bloom_minimal(void **state)
{
    struct gc_arena gc = gc_new();
    struct bloom_filter *bf = bloom_create(2048, 3, &gc);

    int item = 0xbabe;

    bloom_add(bf, (const uint8_t *) &item, sizeof(item));
    assert_int_equal(bloom_test(bf, (const uint8_t *) &item, sizeof(item)), 1);

    item = 0xf00f;
    assert_int_equal(bloom_test(bf, (const uint8_t *) &item, sizeof(item)), 0);

    bloom_free(bf);
    gc_free(&gc);
}

static void
test_reflect_reflect_bloom_simple(void **state)
{
    struct initial_packet_rate_limit *irl = initial_rate_limit_init(INT_MAX, 300, NULL);

    reflect_add_filter_tier(&irl->bloom_conf, &irl->gc, true, 32, 50);
    reflect_add_filter_tier(&irl->bloom_conf, &irl->gc, true, 56, 200);
    init_bloom_filter(irl);

    struct openvpn_sockaddr from = { 0 };
    from.addr.in6.sin6_family = AF_INET6;
    from.addr.in6.sin6_port = random();
    from.addr.in6.sin6_addr.s6_addr[15] = 1;  /* ::1 */

    /* There are 50 attempts that should work until one fails */
    for (int i = 0; i < 50; i++)
    {
        assert_true(reflect_filter_check(irl, &from));
    }

    /* 2002::1 */
    struct openvpn_sockaddr from2 = from;
    from2.addr.in6.sin6_addr.s6_addr[0] = 0x7;
    from2.addr.in6.sin6_addr.s6_addr[1] = 0x7;

    assert_true(reflect_filter_check(irl, &from2));

    /* Any more attempts from ::1 should fail */
    assert_false(reflect_filter_check(irl, &from));

    initial_rate_limit_free(irl);
}

static void
test_reflect_bloom_netmask_masking(void **state)
{
    struct initial_packet_rate_limit *irl = initial_rate_limit_init(INT_MAX, 300, NULL);

    reflect_add_filter_tier(&irl->bloom_conf, &irl->gc, true, 45, 10);
    init_bloom_filter(irl);

    struct openvpn_sockaddr from = { 0 };
    from.addr.in6.sin6_family = AF_INET6;
    from.addr.in6.sin6_port = random();
    for (int i = 0; i < 15; i++)
    {
        from.addr.in6.sin6_addr.s6_addr[i] = random();
    }

    for (int i = 0; i < 10; i++)
    {
        /* /45 means that if we leave the leave first 8 bytes and 5 bits
         * untouched, it is still the same subnet  */
        for (int j = 8; j<15; j++)
        {
            from.addr.in6.sin6_addr.s6_addr[j] = random();
            from.addr.in6.sin6_addr.s6_addr[7] ^= random() & 0x7;
        }
        assert_true(reflect_filter_check(irl, &from));

    }

    /* testing the last IP again should give us a negative result */
    assert_false(reflect_filter_check(irl, &from));

    initial_rate_limit_free(irl);
}


static void
test_reflect_reflect_bloom_mapped(void **state)
{
    struct initial_packet_rate_limit *irl = initial_rate_limit_init(INT_MAX, 300, NULL);

    reflect_add_filter_tier(&irl->bloom_conf, &irl->gc, false, 24, 50);
    reflect_add_filter_tier(&irl->bloom_conf, &irl->gc, false, 8, 80);
    init_bloom_filter(irl);

    /* Our OpenVPN server will not receive IPv4 as well as IPv4 mapped
     * addresses in the same process but for the unit test it is convient
     * to see if they actually mapped to the same entries */

    struct openvpn_sockaddr mapped_v4 =  { 0 };
    mapped_v4.addr.in6.sin6_family = AF_INET6;
    mapped_v4.addr.in6.sin6_port = random();
    /* ::ffff:192.168.0.99 */
    mapped_v4.addr.in6.sin6_addr.s6_addr[10] = 0xff;
    mapped_v4.addr.in6.sin6_addr.s6_addr[11] = 0xff;
    mapped_v4.addr.in6.sin6_addr.s6_addr[12] = 192;
    mapped_v4.addr.in6.sin6_addr.s6_addr[13] = 168;
    mapped_v4.addr.in6.sin6_addr.s6_addr[14] = 0;
    mapped_v4.addr.in6.sin6_addr.s6_addr[15] = 99;

    assert_true(IN6_IS_ADDR_V4MAPPED(&mapped_v4.addr.in6.sin6_addr));

    /* Not the same address but in the same /8 */
    struct openvpn_sockaddr v4addr = {0 };
    v4addr.addr.in4.sin_family = AF_INET;
    v4addr.addr.in4.sin_port = random();
    /* 192.168.123.244 */
    v4addr.addr.in4.sin_addr.s_addr = htonl(0xc0a87bf4);

    /* check that we run into the 50 limit with our mapped address */
    for (int i = 0; i < 50; i++)
    {
        assert_true(reflect_filter_check(irl, &mapped_v4));
    }
    assert_false(reflect_filter_check(irl, &mapped_v4));


    /* Check that the non-mapped IPv4 address uses the same /8 subnet limit */
    for (int i = 0; i < 30; i++)
    {
        assert_true(reflect_filter_check(irl, &v4addr));
    }
    assert_false(reflect_filter_check(irl, &v4addr));

    initial_rate_limit_free(irl);
}


static void
test_bloom_access_functions(void **state)
{
    static_assert(BLOOM_FILTER_BITS_COUNT == 2, "unit test not in sync");
    static_assert(BLOOM_FILTER_BITS_MASK == 0x3, "unit test not in sync");
}


int
main(void)
{
    openvpn_unit_test_setup();
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_bloom_access_functions),
        cmocka_unit_test(test_bloom),
        cmocka_unit_test(test_bloom_minimal),
        cmocka_unit_test(test_reflect_reflect_bloom_simple),
        cmocka_unit_test(test_reflect_reflect_bloom_mapped),
        cmocka_unit_test(test_reflect_bloom_netmask_masking),
        cmocka_unit_test(test_reflect_ddos),
    };


    int ret = cmocka_run_group_tests_name("crypto tests", tests, NULL, NULL);

    return ret;
}
