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

/* This file implements a specialised counting bloom filter implementation
 * used in OpenVPN to mitigate it being used in reflection attacks. The bloom
 * implementation should be general enough to be used in other contexts
 * however */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"


#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "siphash.h"
#include "crypto.h"

#include "bloom.h"


static size_t
calc_ceil_log2(size_t num)
{
    /* Figure out how many bits we have in our hash by doing
     * ceil(log2(bf->size) */

    size_t numbits = 0;
    while (num >>= 1)
    {
        numbits++;
    }
    return numbits;
}

/**
 * Calculate number of bytes needed for each hash function in the bloom filter
 *
 */
static inline size_t
calculate_num_bytes_hashfun(size_t size)
{
    size_t hash_bits = calc_ceil_log2(size);
    /* round up to the nearest byte size */
    size_t hash_bytes = (hash_bits + 7) /8;
    return hash_bytes;
}

/**
 * A bloom filter uses a number of hashes to perform its functionality.
 *
 * Instead of using the same number of siphash function we split the bytes of
 * the siphash to the different hashes.
 *
 * We could also optimise this further by splitting at the bit level but that
 * crates a lot of extra code for bit shifting, etc. so we waste some bits
 *
 * @param bf
 * @param num_hashes
 * @return
 */
size_t
calculate_num_sip_hash_hashes(struct bloom_filter *bf)
{
    size_t hash_bytes = calculate_num_bytes_hashfun(bf->size);
    size_t total_bytes = bf->num_hashes * hash_bytes;

    /* Round up to next SIPHASH_HASH_SIZE */
    size_t num_siphash = (total_bytes + SIPHASH_HASH_SIZE -1) / SIPHASH_HASH_SIZE;

    return num_siphash;
}

/**
 * Calculates the number of bytes we need for storing a bloom filter of size
 * size. We add + 1 to avoid rounding problems and too small allocation */
static inline
size_t
bloom_get_filter_byte_count(size_t size)
{
    static_assert(sizeof(bloom_counter_t) * 8 % BLOOM_FILTER_BITS_COUNT == 0,
                  "bloom_counter_t must be a multiple of BLOOM_FILTER_BIT_COUNT");

    return size * sizeof(bloom_counter_t)/BLOOM_FILTER_BITS_COUNT + 1;
}


static inline
size_t
bloom_get_filter_bit_offset(size_t bucket)
{
    return (bucket * BLOOM_FILTER_BITS_COUNT) % sizeof(bloom_counter_t);
}

static inline
size_t
bloom_get_filter_array_index(size_t bucket)
{
    return (bucket * BLOOM_FILTER_BITS_COUNT) / sizeof(bloom_counter_t);
}

static inline bloom_counter_t
bloom_get_filter_get_counter(struct bloom_filter *bf, size_t bucket)
{
    static_assert((BLOOM_FILTER_BITS_MASK + 1) ==  (1 << BLOOM_FILTER_BITS_COUNT),
                  "BLOOM_FILTER_BITMASK and BLOOM_FILTER_BIT_COUNT are inconsistent");

    bloom_counter_t counter = bf->buckets[bloom_get_filter_array_index(bucket)];
    size_t bitoffset = bloom_get_filter_bit_offset(bucket);

    return (counter >> bitoffset) & BLOOM_FILTER_BITS_MASK;
}

static inline void
bloom_set_filter_counter(struct bloom_filter *bf, size_t bucket, bloom_counter_t value)
{
    bloom_counter_t data = bf->buckets[bloom_get_filter_array_index(bucket)];
    size_t bitoffset = bloom_get_filter_bit_offset(bucket);

    data = data & ~(BLOOM_FILTER_BITS_MASK << bitoffset);

    data = data | ((value & BLOOM_FILTER_BITS_MASK) << bitoffset);

    bf->buckets[bloom_get_filter_array_index(bucket)] = data;
}

/**
 * Creates a new bloom filter structure
 * @param size the number of buckets.
 * @return  the newly created bloom filter structure
 */
struct bloom_filter *
bloom_create(size_t size, size_t num_hashes, struct gc_arena *gc)
{
    size_t bloomfilter_bytes = bloom_get_filter_byte_count(size);
    struct bloom_filter *bf = gc_malloc(sizeof(struct bloom_filter) + bloomfilter_bytes,
                                        false, gc);
    bf->size = size;
    bf->num_hashes = num_hashes;

    bf->hash_bytes = calculate_num_bytes_hashfun(size);
    bf->num_siphash = calculate_num_sip_hash_hashes(bf);

    ALLOC_ARRAY_GC(bf->siphash_keys, struct siphash_key, bf->num_siphash, gc);

    bf->siphash_ctx = siphash_cryptolib_init();

    bloom_clear(bf);
    return bf;
}

void
bloom_free(struct bloom_filter *bf)
{
    siphash_cryptolib_uninit(bf->siphash_ctx);
}


/**
 * Clear the bloom filter, making it empty again as if it were freshly created
 * @param bf the bloom structure to clear
 */
void
bloom_clear(struct bloom_filter *bf)
{
    memset(bf->buckets, 0, bloom_get_filter_byte_count(bf->size));

    /* We randomise the bloom filter keys on every clear of the bloom filter
     * to avoid scenarios where an attacker might learn specific pattern
     * that could exploit false positives in the bloom filter */
    for (size_t i = 0; i < bf->num_siphash; i++)
    {
        prng_bytes(bf->siphash_keys[i].key, SIPHASH_KEY_SIZE);
    }
}


static bloom_counter_t
bloom_add_test(struct bloom_filter *bf, const uint8_t *item, size_t len, bloom_counter_t inc)
{
    uint8_t result[SIPHASH_HASH_SIZE];
    size_t j = 0;
    size_t idx = 0;
    bloom_counter_t ret = bloom_counter_max;

    for (size_t i = 0; i < bf->num_hashes; i++)
    {
        size_t bucket = 0;
        for (int k = 0; k < bf->hash_bytes; k++)
        {
            if (idx == 0)
            {
                /* We have no longer unused bytes in result, generate the next hash */
                siphash(bf->siphash_ctx, item, len, bf->siphash_keys[j++].key,
                        result, SIPHASH_HASH_SIZE);
            }

            bucket = bucket << 8;
            bucket |= result[idx];

            idx = (idx + 1) % SIPHASH_HASH_SIZE;
        }

        bucket = bucket % bf->size;
        bloom_counter_t value = bloom_get_filter_get_counter(bf, bucket);

        ret = min_bloom_counter(ret, value);

        if (inc)
        {
            value = min_bloom_counter(bloom_counter_max, value + 1);
            bloom_set_filter_counter(bf, bucket, value);
        }
    }
    return ret;
}


bloom_counter_t
bloom_add(struct bloom_filter *bf, const uint8_t *item, size_t len)
{
    return bloom_add_test(bf, item, len, 1);
}

bloom_counter_t
bloom_remove(struct bloom_filter *bf, const uint8_t *item, size_t len)
{
    return bloom_add_test(bf, item, len, -1);
}


bloom_counter_t
bloom_test(struct bloom_filter *bf, const uint8_t *item, size_t len)
{
    return bloom_add_test(bf, item, len, 0);
}
