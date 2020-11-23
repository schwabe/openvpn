/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2021 Arne Schwabe <arne@rfc2549.org>
 *  Copyright (C) 2021 OpenVPN Inc <sales@openvpn.net>
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

#include "errlevel.h"
#include "networking.h"

#include "multi.h"
#include "dco.h"
#include "networking_linuxdco.h"

#if defined(ENABLE_DCO)
#include "ssl_verify.h"

bool
dco_do_key_dance(struct tuntap *tt, struct tls_multi *multi, const char *ciphername)
{
    struct key_state *primary = tls_select_encryption_key(multi);
    struct key_state *secondary = NULL;

    for (int i = 0; i < KEY_SCAN_SIZE; ++i)
    {
        struct key_state *ks = get_key_scan(multi, i);
        struct key_ctx_bi *key = &ks->crypto_options.key_ctx_bi;

        if (ks == primary)
        {
            continue;
        }

        if (ks->state >= S_GENERATED_KEYS && ks->authenticated == KS_AUTH_TRUE)
        {
            ASSERT(ks->authenticated == KS_AUTH_TRUE);
            ASSERT(key->initialized);

            secondary = ks;
        }
    }

    if (!primary)
    {
        if (multi->dco_keys_installed >= 1)
        {
            msg(D_DCO, "DCO: No encryption key found. Purging data channel keys");
            dco_del_key(tt, multi->peer_id, OVPN_KEY_SLOT_PRIMARY);
            if (multi->dco_keys_installed == 2)
            {
                dco_del_key(tt, multi->peer_id, OVPN_KEY_SLOT_SECONDARY);
            }
            multi->dco_keys_installed = 2;
        }
        return false;
    }

    /* All keys installed as they should */
    if (primary->dco_status == DCO_INSTALLED_PRIMARY
        && (!secondary || secondary->dco_status == DCO_INSTALLED_SECONDARY))
    {
        /* Check if we have a previously installed secondary key */
        if (!secondary && multi->dco_keys_installed == 2)
        {
            multi->dco_keys_installed = 1;
            dco_del_key(tt, multi->peer_id, OVPN_KEY_SLOT_SECONDARY);
        }
        return true;
    }

    int pid = primary->key_id;
    int sid = secondary ? secondary->key_id : -1;

    msg(D_DCO_DEBUG, "Installing DCO data channel keys for peer %d, "
                     "primary key-id: %d, secondary key-id: %d.",
                     multi->peer_id, pid, sid);

    /* General strategy, get primary key installed correctly first. If that is
     * okay then check if we need to exchange secondary */
    if (primary->dco_status != DCO_INSTALLED_PRIMARY)
    {
        /* ovpn-win-dco does not like to have the install as secondary and then
          * swap to primary for the first key .... */
        if (multi->dco_keys_installed == 0)
        {
            dco_new_key(tt, multi->peer_id, OVPN_KEY_SLOT_PRIMARY, primary, ciphername);
            multi->dco_keys_installed = 1;
        }
        else
        {
            if (primary->dco_status != DCO_INSTALLED_SECONDARY)
            {
                dco_new_key(tt, multi->peer_id, OVPN_KEY_SLOT_SECONDARY, primary, ciphername);
            }
            dco_swap_keys(tt, multi->peer_id);
        }
        primary->dco_status = DCO_INSTALLED_PRIMARY;

        /* if the secondary was installed as primary before the swap demoted
         * it to secondary */
        if (secondary && secondary->dco_status == DCO_INSTALLED_PRIMARY)
        {
            secondary->dco_status = DCO_INSTALLED_SECONDARY;
            multi->dco_keys_installed = 2;
        }
    }

    /* The primary key is now the correct key but the secondary key might
     * already a new key that will be later promoted to primary key and we
     * need to install the key */
    if (secondary && secondary->dco_status != DCO_INSTALLED_SECONDARY)
    {
        dco_new_key(tt, multi->peer_id, OVPN_KEY_SLOT_SECONDARY, secondary, ciphername);
        secondary->dco_status = DCO_INSTALLED_SECONDARY;
        multi->dco_keys_installed = 2;
    }
    /* delete an expired key */
    if (!secondary && multi->dco_keys_installed == 2)
    {
        dco_del_key(tt, multi->peer_id, OVPN_KEY_SLOT_SECONDARY);
        multi->dco_keys_installed = 1;
    }

    /* All keys that we have not installed are set to NOT installed */
    for (int i = 0; i < KEY_SCAN_SIZE; ++i)
    {
        struct key_state *ks = get_key_scan(multi, i);
        if (ks != primary && ks != secondary)
        {
            ks->dco_status = DCO_NOT_INSTALLED;
        }
    }
    return true;
}

int
get_dco_cipher(const char *cipher)
{
    if (streq(cipher, "AES-256-GCM") || streq(cipher, "AES-128-GCM") ||
        streq(cipher, "AES-192-GCM"))
        return OVPN_CIPHER_ALG_AES_GCM;
    else if (streq(cipher, "CHACHA20-POLY1305"))
    {
        return OVPN_CIPHER_ALG_CHACHA20_POLY1305;
    }
    else if (strcmp(cipher, "none") == 0)
    {
        return OVPN_CIPHER_ALG_NONE;
    }
    else
    {
        return -ENOTSUP;
    }
}
#endif

/* These methods are currently Linux specified but likely to be used any platform that implements Server side DCO */
#if defined(ENABLE_LINUXDCO)

void
dco_install_iroute(struct multi_context *m, struct multi_instance *mi,
                   struct mroute_addr *addr, bool primary)
{
    if (!dco_enabled(&m->top.options))
    {
        return;
    }

    if (primary)
    {
        /* We do not want to install IP -> IP dev ovpn-dco0 */
        return;
    }

   int addrtype = (addr->type & MR_ADDR_MASK);

    /* If we do not have local IP addr to install, skip the route */
    if ((addrtype == MR_ADDR_IPV6 && !mi->context.c2.push_ifconfig_ipv6_defined)
        || (addrtype == MR_ADDR_IPV4 && !mi->context.c2.push_ifconfig_defined))
    {
        return;
    }

    struct context *c = &mi->context;
    const char *dev = c->c1.tuntap->actual_name;

    if (addrtype == MR_ADDR_IPV6)
    {
        net_route_v6_add(&m->top.net_ctx, &addr->v6.addr, addr->netbits,
                         &mi->context.c2.push_ifconfig_ipv6_local, dev, 0,
                         DCO_IROUTE_METRIC);
    }
    else if (addrtype == MR_ADDR_IPV4)
    {
        in_addr_t dest = htonl(addr->v4.addr);
        net_route_v4_add(&m->top.net_ctx, &dest, addr->netbits,
                         &mi->context.c2.push_ifconfig_local, dev, 0,
                         DCO_IROUTE_METRIC);
    }
}

void
dco_delete_iroutes(struct multi_context *m, struct multi_instance *mi)
{
    if (!dco_enabled(&m->top.options))
    {
        return;
    }
    ASSERT(TUNNEL_TYPE(mi->context.c1.tuntap) == DEV_TYPE_TUN);

    struct context *c = &mi->context;
    const char *dev = c->c1.tuntap->actual_name;

    if (mi->context.c2.push_ifconfig_defined)
    {
        for (const struct iroute *ir = c->options.iroutes; ir != NULL; ir = ir->next)
        {
            net_route_v4_del(&m->top.net_ctx, &ir->network, ir->netbits,
                             &mi->context.c2.push_ifconfig_local, dev,
                             0, DCO_IROUTE_METRIC);
        }
    }

    if (mi->context.c2.push_ifconfig_ipv6_defined)
    {
        for (const struct iroute_ipv6 *ir6 = c->options.iroutes_ipv6; ir6 != NULL; ir6 = ir6->next)
        {
            net_route_v6_del(&m->top.net_ctx, &ir6->network, ir6->netbits,
                             &mi->context.c2.push_ifconfig_ipv6_local, dev,
                             0, DCO_IROUTE_METRIC);
        }
    }
}
#else
void
dco_install_iroute(struct multi_context *m, struct multi_instance *mi,
                   struct mroute_addr *addr, bool primary)
{
}

void
dco_delete_iroutes(struct multi_context *m, struct multi_instance *mi)
{
}
#endif