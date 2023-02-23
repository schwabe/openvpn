/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2023 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2023 Arne Schwabe <arne@rfc2549.org>
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

#include "siphash.h"
#include "buffer.h"


#ifdef ENABLE_CRYPTO_OPENSSL
#include <openssl/opensslv.h>
#endif

#if defined(ENABLE_CRYPTO_OPENSSL) && OPENSSL_VERSION_NUMBER >= 0x30000000L

#include <openssl/evp.h>
#include "crypto_openssl.h"

struct siphash_context
{
    EVP_MAC *mac;
    EVP_MAC_CTX *ctx;
    size_t size;
    OSSL_PARAM params[3];
};

/*
 *  Computes a SipHash value
 * in: pointer to input data (read-only)
 *  inlen: input data length in bytes (any size_t value)
 * k: pointer to the key data (read-only), must be 16 bytes
 * out: pointer to output data (write-only), outlen bytes must be allocated
 *  outlen: length of the output in bytes, must be 8 or 16
 */
int
siphash_cryptolib(void *sip_context, const void *in, const size_t inlen,
                  const void *k, uint8_t *out, const size_t outlen)
{
    struct siphash_context *sip = sip_context;


    sip->params[1] = OSSL_PARAM_construct_octet_string("key", (void *)k,
                                                       SIPHASH_KEY_SIZE);
    if (!EVP_MAC_init(sip->ctx, NULL, 0, sip->params))
    {
        crypto_msg(M_FATAL, "EVP_MAC_init failed");
    }
    EVP_MAC_update(sip->ctx, in, inlen);

    size_t outl = 0;
    EVP_MAC_final(sip->ctx, out, &outl, outlen);
    return 0;
}

void *
siphash_cryptolib_init(void)
{
    struct siphash_context *sip;
    ALLOC_OBJ(sip, struct siphash_context);

    sip->mac = EVP_MAC_fetch(NULL, "SIPHASH", NULL);
    if (!sip->mac)
    {
        /* Our OpenSSL library does not support SIPHASH */
        return sip;
    }
    sip->ctx = EVP_MAC_CTX_new(sip->mac);

    /* OpenSSL will truly hold a pointer to an int in that parameter */
    sip->size = SIPHASH_HASH_SIZE;
    sip->params[0] = OSSL_PARAM_construct_size_t("size", &sip->size);
    /* params[1] will hold the key that changes which each invocation */
    sip->params[2] = OSSL_PARAM_construct_end();
    return sip;
}

bool
siphash_cryptolib_available(void *sip_context)
{
    struct siphash_context *sip = sip_context;

    return (bool)(sip->mac);
}

void
siphash_cryptolib_uninit(void *sip_context)
{
    struct siphash_context *sip = sip_context;
    EVP_MAC_CTX_free(sip->ctx);
    EVP_MAC_free(sip->mac);
    free(sip_context);
}

#else  /* if defined(ENABLE_CRYPTO_OPENSSL) && OPENSSL_VERSION_NUMBER >= 0x30000000L */
/* for now, we only have one implementation of SIPHASH in a libray, so put the
 * dummy functions also here */
int
siphash_cryptolib(void *sip_context, const void *in, const size_t inlen,
                  const void *k, uint8_t *out, const size_t outlen)
{
    return -1;
}

bool
siphash_cryptolib_available(void *sip_context)
{
    return false;
}

void *
siphash_cryptolib_init(void)
{
    return NULL;
}

void
siphash_cryptolib_uninit(void *sip_context)
{
}


#endif /* if defined(ENABLE_CRYPTO_OPENSSL) && OPENSSL_VERSION_NUMBER >= 0x30000000L */
