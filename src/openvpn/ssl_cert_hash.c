/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2026 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2026 Arne Schwabe <arne@rfc2549.org>
 *
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

#include "ssl_cert_hash.h"
#include "buffer.h"
#include "ssl_verify.h"

void
cert_hash_remember(struct tls_session *session, const int error_depth,
                   const struct buffer *cert_hash)
{
    if (error_depth >= 0 && error_depth < MAX_CERT_DEPTH)
    {
        if (!session->cert_hash_set)
        {
            ALLOC_OBJ_CLEAR(session->cert_hash_set, struct cert_hash_set);
        }
        if (!session->cert_hash_set->ch[error_depth])
        {
            ALLOC_OBJ(session->cert_hash_set->ch[error_depth], struct cert_hash);
        }

        struct cert_hash *ch = session->cert_hash_set->ch[error_depth];
        ASSERT(sizeof(ch->sha256_hash) == BLEN(cert_hash));
        memcpy(ch->sha256_hash, BPTR(cert_hash), sizeof(ch->sha256_hash));
    }
}

void
cert_hash_free(struct cert_hash_set *chs)
{
    if (chs)
    {
        int i;
        for (i = 0; i < MAX_CERT_DEPTH; ++i)
        {
            free(chs->ch[i]);
        }
        free(chs);
    }
}

bool
cert_hash_compare(const struct cert_hash_set *chs1, const struct cert_hash_set *chs2)
{
    if (chs1 && chs2)
    {
        int i;
        for (i = 0; i < MAX_CERT_DEPTH; ++i)
        {
            const struct cert_hash *ch1 = chs1->ch[i];
            const struct cert_hash *ch2 = chs2->ch[i];

            if (!ch1 && !ch2)
            {
                continue;
            }
            else if (ch1 && ch2
                     && !memcmp(ch1->sha256_hash, ch2->sha256_hash, sizeof(ch1->sha256_hash)))
            {
                continue;
            }
            else
            {
                return false;
            }
        }
        return true;
    }
    else if (!chs1 && !chs2)
    {
        return true;
    }
    else
    {
        return false;
    }
}

static struct cert_hash_set *
cert_hash_copy(const struct cert_hash_set *chs)
{
    struct cert_hash_set *dest = NULL;
    if (chs)
    {
        int i;
        ALLOC_OBJ_CLEAR(dest, struct cert_hash_set);
        for (i = 0; i < MAX_CERT_DEPTH; ++i)
        {
            const struct cert_hash *ch = chs->ch[i];
            if (ch)
            {
                ALLOC_OBJ(dest->ch[i], struct cert_hash);
                memcpy(dest->ch[i]->sha256_hash, ch->sha256_hash, sizeof(dest->ch[i]->sha256_hash));
            }
        }
    }
    return dest;
}

void
tls_lock_cert_hash_set(struct tls_multi *multi)
{
    const struct cert_hash_set *chs = multi->session[TM_ACTIVE].cert_hash_set;
    if (chs && !multi->locked_cert_hash_set)
    {
        multi->locked_cert_hash_set = cert_hash_copy(chs);
    }
}
