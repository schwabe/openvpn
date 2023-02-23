/*
 * SipHash reference C implementation
 *
 * Copyright (c) 2012-2021 Jean-Philippe Aumasson
 * <jeanphilippe.aumasson@gmail.com>
 * Copyright (c) 2012-2014 Daniel J. Bernstein <djb@cr.yp.to>
 *
 * To the extent possible under law, the author(s) have dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide. This software is distributed without any warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication along
 * with
 * this software. If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#ifndef SIPHASH_H
#define SIPHASH_H

#include <inttypes.h>
#include <string.h>
#include <stdbool.h>

/* siphash always uses 128-bit keys */
#define SIPHASH_KEY_SIZE    16
#define SIPHASH_HASH_SIZE   16


/* Prototypes for an implementation of SIPHASH in a crypto library */

/**
 * Calculates SIPHASH using the crypto library function.
 */
int
siphash_cryptolib(void *sip_context, const void *in, size_t inlen,
                  const void *k, uint8_t *out, size_t outlen);

/**
 * Calculates SIPHASH using the reference implementation
 */
int
siphash_reference(const void *in, size_t inlen, const void *k,
                  uint8_t *out, size_t outlen);

void *
siphash_cryptolib_init(void);

void
siphash_cryptolib_uninit(void *sip_context);

bool
siphash_cryptolib_available(void *sip_context);

static inline
int
siphash(void *ctx, const void *in, size_t inlen, const void *k,
        uint8_t *out, size_t outlen)
{
    if (siphash_cryptolib_available(ctx) && false)
    {
        return siphash_cryptolib(ctx, in, inlen, k, out, outlen);
    }
    else
    {
        return siphash_reference(in, inlen, k, out, outlen);
    }

}

#endif /* ifndef SIPHASH_H */
