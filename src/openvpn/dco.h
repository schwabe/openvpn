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
#ifndef DCO_H
#define DCO_H

/* forward declarations, including multi.h leads to nasty include
 * order problems */
struct multi_context;
struct tls_multi;
struct multi_instance;
struct mroute_addr;
struct tuntap;

#if !defined(ENABLE_DCO)
/* Define dummy type for dco context if DCO is not enabled */
typedef void *dco_context_t;

static inline void open_tun_dco(struct tuntap *tt, const char* dev) { ASSERT(false); }

static inline void close_tun_dco(struct tuntap *tt) { ASSERT(false); }
#else
#include "networking_windco.h"
#include "networking_linuxdco.h"
#include "crypto.h"

/* forward declarations */
struct tuntap;
struct key_state;

void open_tun_dco(struct tuntap *tt, const char* dev);

void close_tun_dco(struct tuntap *tt);

int dco_new_peer(struct tuntap *tt, unsigned int peerid, int sd,
                 struct sockaddr *localaddr, struct sockaddr *remoteaddr,
                 struct in_addr *remote_in4, struct in6_addr *remote_in6);


int ovpn_set_peer(struct tuntap *tt, unsigned  int peerid,
                  unsigned int keepalive_interval,
                  unsigned int keepalive_timeout);

int ovpn_do_read_dco(struct dco_context *dco);
int dco_del_peer(struct tuntap *tt, unsigned int peerid);

int
dco_del_key(struct tuntap *tt, unsigned int peerid, ovpn_key_slot_t slot);

int
dco_new_key(struct tuntap *tt, unsigned int peerid, ovpn_key_slot_t slot,
            struct key_state *ks, const char* ciphername);

int dco_swap_keys(struct tuntap *tt, unsigned int peerid);

/**
 * Does the assertions that the key material is indeed sane.
 * @param key   the key context to be checked
 */
static inline void dco_check_key_ctx(const struct key_ctx_bi *key)
{
    ASSERT(key->initialized);
    /* Double check that we do not have empty keys */
    const uint8_t empty_key[32] = { 0 };
    ASSERT(memcmp(key->encrypt.aead_key, empty_key, 32));
    ASSERT(memcmp(key->decrypt.aead_key, empty_key, 32));
}

#endif

void
dco_install_iroute(struct multi_context *m, struct multi_instance *mi,
                   struct mroute_addr *addr, bool primary);

void
dco_delete_iroutes(struct multi_context *m, struct multi_instance *mi);


/**
 * This function will check if the encryption and decryption keys are installed
 * to the data channel offload and if not do the necessary steps to ensure that
 * openvpn and data channel are synced again
 *
 * @param tt            Tun tap device context
 * @param multi         TLS multi instance
 * @param ciphername    Ciphername to use when installing the keys.
 * @return
 */
bool
dco_do_key_dance(struct tuntap *tt, struct tls_multi *multi, const char *ciphername);

/**
 * Translates an OpenVPN Cipher string to a supported cipher enum from DCO
 * @param cipher OpenVPN cipher string
 * @return constant that defines the cipher or -ENOTSUP if not supported
 */
int get_dco_cipher(const char *cipher);
#endif