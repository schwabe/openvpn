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
#ifndef REFLECT_FILTER_H
#define REFLECT_FILTER_H

#include <limits.h>
#include "socket.h"
#include "bloom.h"

struct filter_tier {
    struct filter_tier *next;

    int limit;
    int netmask;

    /** The number of packets we dropped since we went over this limit */
    size_t dropped;
};

struct bloom_filter_conf {
    struct filter_tier *inet_tiers;
    struct filter_tier *inet6_tiers;

    /* Configuration of the bloom filter */
    size_t num_hashes;
    size_t size;
};


/** struct that handles all the rate limiting logic for initial
 * responses */
struct initial_packet_rate_limit {
    /** This is a hard limit for packets per seconds. */
    int64_t max_per_period;

    /** period length in seconds */
    int period_length;

    /** Number of packets in the current period. We use int64_t here
     * to avoid any potential issues with overflow */
    int64_t curr_period_counter;

    /* Last time we reset our timer */
    time_t last_period_reset;

    /* we want to warn once per period that packets are being started to
     * be dropped */
    bool warning_displayed;

    struct bloom_filter_conf bloom_conf;
    struct bloom_filter *bf;

    /* gc_arena used for the various allocations by this struct */
    struct gc_arena gc;
};

/**
 * Adds a bloom filter tier to the bloom filter config.
 */
void
reflect_add_filter_tier(struct bloom_filter_conf *bfconf, struct gc_arena *gc,
                        bool ipv6, int netmask, int limit);

/**
 * checks if the connection is still allowed to connect under the rate
 * limit. This also increases the internal counter at the same time
 */
bool
reflect_filter_check(struct initial_packet_rate_limit *irl,
                     struct openvpn_sockaddr *from);

/**
 * decreases the counter of initial packets seen, so connections that
 * successfully completed the three-way handshake do not count against
 * the counter of initial connection attempts
 */
void
reflect_filter_rate_limit_decrease(struct initial_packet_rate_limit *irl,
                                   struct openvpn_sockaddr *from);

/**
 * allocate and initialize the initial-packet rate limiter structure
 *
 * Note: this function does not copy bconf's contents.
 */
struct initial_packet_rate_limit *
initial_rate_limit_init(int max_per_period, int period_length,
                        struct bloom_filter_conf *bconf);

/**
 * free the initial-packet rate limiter structure
 */
void initial_rate_limit_free(struct initial_packet_rate_limit *irl);

/**
 * Initialises the bloom filter with the configuration values of
 * irl->bloom_conf
 */
void
init_bloom_filter(struct initial_packet_rate_limit *irl);
#endif /* ifndef REFLECT_FILTER_H */
