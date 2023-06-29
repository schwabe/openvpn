/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2022 OpenVPN Inc <sales@openvpn.net>
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

#ifndef BLOOM_H
#define BLOOM_H

#include <stdint.h>
#include "siphash.h"
#include "buffer.h"

/* This is the type we use for the buckets. This is split into small buckets
 * with BLOOM_FILTER_BIT_COUNT size */
typedef uint32_t bloom_counter_t;
#define BLOOM_FILTER_BITS_COUNT    2
#define BLOOM_FILTER_BITS_MASK   0x03
#define bloom_counter_max        0x03


static inline bloom_counter_t
min_bloom_counter(bloom_counter_t x, bloom_counter_t y)
{
    if (x < y)
    {
        return x;
    }
    else
    {
        return y;
    }
}

struct siphash_key {
    uint8_t key[SIPHASH_KEY_SIZE];
};

struct bloom_filter {
    /** Size of the bloom filter in entries, ie total bits/bits per counter */
    size_t size;

    /** Number of bytes used by each hash function:
     *
     * log2(size * 8) bits rounded up to the next byte
     *
     * This is a cached value since log2 is surprisingly slow
     * (5% of total time of if we do not cache it) */
    size_t hash_bytes;

    /** number of hashes we use to determine the bit positions */
    size_t num_hashes;
    /** number of siphash function needed to calculate. This can be
     * calculated from the other members of the struct but we store it
     * in the struct for fast access */
    size_t num_siphash;

    /** keys for the siphash functions */
    struct siphash_key *siphash_keys;

    /** the actual buckets that hold the data */
    bloom_counter_t buckets[];
};


struct bloom_filter *
bloom_create(size_t size, size_t num_hashes, struct gc_arena *gc);

bloom_counter_t
bloom_test(struct bloom_filter *bf, const uint8_t *item, size_t len);

bloom_counter_t
bloom_add(struct bloom_filter *bf, const uint8_t *item, size_t len);

bloom_counter_t
bloom_remove(struct bloom_filter *bf, const uint8_t *item, size_t len);

void
bloom_clear(struct bloom_filter *bf);
#endif /* ifndef BLOOM_H */
