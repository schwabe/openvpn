/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2022-2024 OpenVPN Inc <sales@openvpn.net>
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


#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <memory.h>

#include "crypto.h"
#include "reflect_filter.h"

static bool
reflect_filter_rate_limit_check(struct initial_packet_rate_limit *irl)
{
    if (now > irl->last_period_reset + irl->period_length)
    {
        int64_t dropped = irl->curr_period_counter - irl->max_per_period;
        if (dropped > 0)
        {
            msg(D_TLS_DEBUG_LOW, "Dropped %" PRId64 " initial handshake packets"
                " due to --connect-freq-initial %" PRId64 " %d", dropped,
                irl->max_per_period, irl->period_length);

        }
        irl->last_period_reset = now;
        irl->curr_period_counter = 0;
        irl->warning_displayed = false;
    }

    irl->curr_period_counter++;

    bool over_limit = irl->curr_period_counter > irl->max_per_period;

    if (over_limit && !irl->warning_displayed)
    {
        msg(M_WARN, "Note: --connect-freq-initial %" PRId64 " %d rate limit "
            "exceeded, dropping initial handshake packets for the next %d "
            "seconds", irl->max_per_period, irl->period_length,
            (int)(irl->last_period_reset + irl->period_length - now));
        irl->warning_displayed = true;
    }
    return !over_limit;
}

static void
reset_filter_tier(struct initial_packet_rate_limit *irl,
                  struct filter_tier *tier, const char *prefix)
{
    for (; tier != NULL; tier = tier->next)
    {
        if (tier->dropped > 0)
        {
            msg(D_TLS_DEBUG_LOW, "Dropped %zu initial handshake packets due to "
                "--connect-freq-initial-bloom-limit %s %d %d",
                tier->dropped, prefix, tier->netmask, tier->limit);
            tier->dropped = 0;
        }
    }
}

static void
bloom_filter_check_reset(struct initial_packet_rate_limit *irl)
{
    if (now > irl->last_period_reset + irl->period_length)
    {
        reset_filter_tier(irl, irl->bloom_conf.inet_tiers, "inet");
        reset_filter_tier(irl, irl->bloom_conf.inet6_tiers, "inet6");

        bloom_clear(irl->bf);
    }
}


/**
 * structure used as lookup key for the bloom structure. We used the
 * netmask as part of the structure to avoid the look for the first
 * IP of a subnet and the subnet to be same key.
 */
struct bloom_filter_key {
    union {
        struct in_addr in;
        struct in6_addr in6;
    };
    int netmask;
    /* we keep the count in the key instead of in the bloom filter table as
     * can then keep the counter in the bloom filter itself small (2 bits)
     * and bloom filter usage is the same for 20000 request from the same IP
     * (20k entries with different count but same IP) and from 20000 random ips
     * (20k entries with count 1 but different IP) */
    int count;
};

static inline struct bloom_filter_key
filter_mask_inet6(struct openvpn_sockaddr *addr, int netmask)
{
    struct bloom_filter_key ret = { 0 };
    ret.in6 = addr->addr.in6.sin6_addr;

    int bits_to_clear = 128 - netmask;
    int bytes_to_clear =  bits_to_clear /8;
    bits_to_clear = bits_to_clear % 8;

    memset(&ret.in6.s6_addr[15 - bytes_to_clear], 0x00, bytes_to_clear);

    ret.in6.s6_addr[15 - bytes_to_clear - 1] &= (0xff << bits_to_clear);

    ret.netmask = netmask;

    return ret;
}

static inline struct bloom_filter_key
filter_mask_inet(struct openvpn_sockaddr *addr, int netmask)
{
    struct bloom_filter_key ret = { 0 };
    ret.in = addr->addr.in4.sin_addr;
    ret.in.s_addr &= htonl(0xffffffff << (32 - netmask));
    ret.netmask = netmask;
    return ret;
}

/* We use one function and an action argument to avoid repeating
 * the code to iterate to the tiers and the creating the lookup
 * keys */
enum bloom_filter_action
{
    REFLECT_CHECK,
    REFLECT_INCREASE,
    REFLECT_DECREASE,
};

static int
reflect_lookup_bf_key(struct bloom_filter *bf, struct bloom_filter_key *key, int limit)
{
    /* we do a lookup for 1,2,3, and 4 and the limit first
     * and after that do regular binary search. This is meant to optimise
     * the common case where just a small number of requests are coming from
     * each IP */
    key->count = limit;
    if (bloom_test(bf, (const uint8_t *) key, sizeof(struct bloom_filter_key)) > 0)
    {
        return limit;
    }

    key->count = 4;
    if (bloom_test(bf, (const uint8_t *) key, sizeof(struct bloom_filter_key)) == 0)
    {
        /* The value for 4 has not been found, so the real value might be 1, 2, or 3. */
        for (int i = 3; i > 0; i--)
        {
            key->count = i;
            if (bloom_test(bf, (const uint8_t *) key, sizeof(struct bloom_filter_key)) > 0)
            {
                return i;
            }
        }

        /* 4 was no in the map and 1-3 are also not there, so assume the key is not in the map */
        return 0;
    }

    int low = 3;
    int high = limit;

    while (low < high)
    {

        key->count = (high + low + 1)/2;
        bloom_counter_t count = bloom_test(bf, (const uint8_t *) key, sizeof(struct bloom_filter_key));
        if (count > 0)
        {
            low = key->count;
        }
        else
        {
            high = key->count - 1;
        }
    }

    if (low == 4)
    {
        /* we reached the lower end of our binary search have not found the
         * key and we know that 4 is in the map */
        return 4;
    }
    else
    {
        return low;
    }
}

/**
 * Convert a mapped IPv6 mapped IPv4 address (::ffff:0:0/96) to an
 * equivalent IPv4 adress.
 *
 * @note: This function only converts the IP itself and ignores other
 * parts of the \c from structure like port or protocol.
 */
static struct openvpn_sockaddr
convert_mapped_inet_sockaddr(struct openvpn_sockaddr *from)
{
    struct openvpn_sockaddr from_mapped = { 0 };
    /* we ignore the fields like port that the key in the bloom filter
     * ignores too. This makes this function non-generic */

    from_mapped.addr.in4.sin_family = AF_INET;

    memcpy(&from_mapped.addr.in4.sin_addr.s_addr,
           &from->addr.in6.sin6_addr.s6_addr[12],
           sizeof(from_mapped.addr.in4.sin_addr.s_addr));

    return from_mapped;
}

static bool
bloom_filter_action(struct initial_packet_rate_limit *irl,
                    struct openvpn_sockaddr *from,
                    enum bloom_filter_action action)
{
    bool found = false;
    struct filter_tier *tier = NULL;

    struct openvpn_sockaddr from_mapped;

    if (from->addr.sa.sa_family == AF_INET6
        && IN6_IS_ADDR_V4MAPPED(&from->addr.in6.sin6_addr))
    {
        from_mapped = convert_mapped_inet_sockaddr(from);
        from = &from_mapped;
    }

    if (from->addr.sa.sa_family == AF_INET)
    {
        tier = irl->bloom_conf.inet_tiers;

    }
    else if (from->addr.sa.sa_family == AF_INET6)
    {
        tier = irl->bloom_conf.inet6_tiers;
    }

    while (tier)
    {
        struct filter_tier *next_tier = tier->next;
        struct bloom_filter_key key;

        if (from->addr.sa.sa_family == AF_INET6)
        {
            key = filter_mask_inet6(from, tier->netmask);
        }
        else
        {
            key = filter_mask_inet(from, tier->netmask);
        }

        /* fetch the current count of the key in the bloom filter */
        int result = reflect_lookup_bf_key(irl->bf, &key, tier->limit);
        struct gc_arena gc = gc_new();
        gc_free(&gc);

        switch (action)
        {

            case REFLECT_CHECK:
                if (result >= tier->limit)
                {
                    found = true;
                    tier->dropped++;
                    if (tier->dropped == 1)
                    {
                        msg(M_WARN, "Note: --connect-freq-initial-bloom-limit "
                            "limit for netmask /%d exceeded. Expect additional "
                            "initial packet drops for the next %d seconds",
                            tier->netmask,
                            (int)(irl->last_period_reset + irl->period_length - now));
                    }
                }
                break;

            case REFLECT_INCREASE:
                ASSERT(result < tier->limit);
                key.count = result + 1;
                bloom_add(irl->bf, (const uint8_t *) &key, sizeof(key));
                break;

            case REFLECT_DECREASE:
                key.count = result - 1;
                bloom_remove(irl->bf, (const uint8_t *) &key, sizeof(key));
                break;
        }

        tier = next_tier;

    }
    if (!found && action == REFLECT_CHECK)
    {
        /* We only want to increase the counters if the IP is not already
         * in the set. */
        bloom_filter_action(irl, from, REFLECT_INCREASE);
    }
    return found;
}

static bool
bloom_filter_check(struct initial_packet_rate_limit *irl,
                   struct openvpn_sockaddr *from)
{
    if (now > irl->last_period_reset + irl->period_length)
    {

        bloom_filter_check_reset(irl);
        bloom_clear(irl->bf);
    }

    return bloom_filter_action(irl, from, REFLECT_CHECK);
}


bool
reflect_filter_check(struct initial_packet_rate_limit *irl,
                     struct openvpn_sockaddr *from)
{
    /* We are doing the bloom filter check first so packets that are already
     * rejected by the bloom filter do not count against the limit of the
     * simple rate limiter */
    if (irl->bf && bloom_filter_check(irl, from))
    {
        return false;
    }

    if (!reflect_filter_rate_limit_check(irl))
    {
        return false;
    }

    return true;
}


void
reflect_filter_rate_limit_decrease(struct initial_packet_rate_limit *irl, struct openvpn_sockaddr *from)
{
    if (irl->bf && bloom_filter_action(irl, from, REFLECT_CHECK))
    {
        /* Only remove if it is actually present. This might be a packet
         * coming from an early period or be relayed */
        bloom_filter_action(irl, from, REFLECT_DECREASE);
    }

    if (irl->curr_period_counter > 0)
    {
        irl->curr_period_counter--;
    }
}

void
reflect_add_filter_tier(struct bloom_filter_conf *bfconf, struct gc_arena *gc,
                        bool ipv6, int netmask, int limit)
{
    struct filter_tier *ftnew = gc_malloc(sizeof(struct filter_tier), true, gc);

    ftnew->netmask = netmask;
    ftnew->limit = limit;

    if (ipv6)
    {
        ftnew->next = bfconf->inet6_tiers;
        bfconf->inet6_tiers = ftnew;
    }
    else
    {
        ftnew->next = bfconf->inet_tiers;
        bfconf->inet_tiers = ftnew;
    }
}

void
init_bloom_filter(struct initial_packet_rate_limit *irl)
{
    if (!irl->bloom_conf.size)
    {
        /* the default allocates 2MB for bloom filter entries */
        irl->bloom_conf.size = 1024ul * 1024 * 8;
    }
    if (!irl->bloom_conf.num_hashes)
    {
        irl->bloom_conf.num_hashes = 7;
    }

    irl->bf = bloom_create(irl->bloom_conf.size, irl->bloom_conf.num_hashes,
                           &irl->gc);
    bloom_clear(irl->bf);
}

struct initial_packet_rate_limit *
initial_rate_limit_init(int max_per_period, int period_length,
                        struct bloom_filter_conf *bconf)
{

    struct initial_packet_rate_limit *irl = NULL;
    ALLOC_OBJ_CLEAR(irl, struct initial_packet_rate_limit);

    irl->gc = gc_new();

    irl->max_per_period = max_per_period;
    irl->period_length = period_length;
    irl->curr_period_counter = 0;
    irl->last_period_reset = 0;

    if (bconf)
    {
        irl->bloom_conf = *bconf;
        init_bloom_filter(irl);
    }

    return irl;
}

void
initial_rate_limit_free(struct initial_packet_rate_limit *irl)
{
    gc_free(&irl->gc);
    free(irl);
    irl = NULL;
}
