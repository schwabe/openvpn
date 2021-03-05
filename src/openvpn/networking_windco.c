/*
 *  Interface to ovpn-win-dco networking code
 *
 *  Copyright (C) 2020 Arne Schwabe <arne@rfc2549.org>
 *  Copyright (C) 2020 OpenVPN Inc <sales@openvpn.net>
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

#if defined(ENABLE_WINDCO)
#include "syshead.h"

#include "networking_windco.h"
#include "dco.h"
#include "tun.h"
#include "crypto.h"
#include "ssl_common.h"


#include <winsock2.h>
#include <ws2tcpip.h>

#if defined(__MINGW32__)
const IN_ADDR in4addr_any = { 0 };
#endif

static struct tuntap create_dco_handle(const char* devname, struct gc_arena *gc)
{
    struct tuntap tt = { 0 };

    tt.windows_driver = WINDOWS_DRIVER_WINDCO;

    const char* device_guid;
    tun_open_device(&tt, devname, &device_guid, gc);
    tt.windows_driver = WINDOWS_DRIVER_WINDCO;

    return tt;
}

void open_tun_dco(struct tuntap *tt, const char* dev)
{
    ASSERT(0);
}

void dco_start_tun(struct tuntap* tt)
{
    msg(D_DCO_DEBUG, "%s", __func__);

    DWORD bytes_returned = 0;
    if (!DeviceIoControl(tt->hand, OVPN_IOCTL_START_VPN, NULL, 0, NULL, 0,
        &bytes_returned, NULL))
    {
        msg(M_ERR, "DeviceIoControl(OVPN_IOCTL_START_VPN) failed with code %lu", GetLastError());
    }
}

struct tuntap
dco_create_socket(struct addrinfo *remoteaddr, bool bind_local,
                  struct addrinfo *bind, const char* devname,
                  struct gc_arena *gc)
{
    msg(D_DCO_DEBUG, "%s", __func__);

    OVPN_NEW_PEER peer = { 0 };

    struct sockaddr *local = NULL;
    struct sockaddr *remote = remoteaddr->ai_addr;

    if (remoteaddr->ai_protocol == IPPROTO_TCP
        || remoteaddr->ai_socktype == SOCK_STREAM)
    {
        peer.Proto = OVPN_PROTO_TCP;
    }
    else
    {
        peer.Proto = OVPN_PROTO_UDP;
    }

    if (bind_local)
    {
        /* Use first local address with correct address family */
        while(bind && !local)
        {
            if (bind->ai_family == remote->sa_family)
            {
                local = bind->ai_addr;
            }
            bind = bind->ai_next;
        }
    }

    if (bind_local && !local)
    {
        msg(M_FATAL, "DCO: Socket bind failed: Address to bind lacks %s record",
           addr_family_name(remote->sa_family));
    }

    if (remote->sa_family == AF_INET6)
    {
        peer.Remote.Addr6 = *((SOCKADDR_IN6 *)(remoteaddr->ai_addr));
        if (local)
        {
            peer.Local.Addr6 = *((SOCKADDR_IN6 *)local);
        }
        else
        {
            peer.Local.Addr6.sin6_addr = in6addr_any;
            peer.Local.Addr6.sin6_port = 0;
            peer.Local.Addr6.sin6_family = AF_INET6;
        }
    }
    else if (remote->sa_family == AF_INET)
    {
        peer.Remote.Addr4 = *((SOCKADDR_IN *)(remoteaddr->ai_addr));
        if (local)
        {
            peer.Local.Addr4 = *((SOCKADDR_IN *)local);
        }
        else
        {
            peer.Local.Addr4.sin_addr = in4addr_any;
            peer.Local.Addr4.sin_port = 0;
            peer.Local.Addr4.sin_family = AF_INET;
        }
    }
    else
    {
        ASSERT(0);
    }

    struct tuntap tt = create_dco_handle(devname, gc);

    if (!DeviceIoControl(tt.hand, OVPN_IOCTL_NEW_PEER, &peer, sizeof(peer), NULL, 0, NULL, NULL))
    {
        msg(M_ERR, "DeviceIoControl(OVPN_IOCTL_NEW_PEER) failed with code %d", GetLastError());
    }
    return tt;
}

int dco_new_peer(struct tuntap *tt, unsigned int peerid, int sd,
                 struct sockaddr *localaddr, struct sockaddr *remoteaddr,
                 struct in_addr *remote_in4, struct in6_addr *remote_in6)
{
    msg(D_DCO_DEBUG, "%s: peer-id %d, fd %d", __func__, peerid, sd);
    return 0;
}

int ovpn_set_peer(struct tuntap *tt, unsigned int peerid,
                  unsigned int keepalive_interval,
                  unsigned int keepalive_timeout)
{
    msg(D_DCO_DEBUG, "%s: peer-id %d, keepalive %d/%d", __func__, peerid,
        keepalive_interval, keepalive_timeout);

    OVPN_SET_PEER peer;

    peer.KeepaliveInterval =  keepalive_interval;
    peer.KeepaliveTimeout = keepalive_timeout;

    DWORD bytes_returned = 0;
    if (!DeviceIoControl(tt->hand, OVPN_IOCTL_SET_PEER, &peer, sizeof(peer), NULL, 0, &bytes_returned, NULL))
    {
        msg(M_WARN, "DeviceIoControl(OVPN_IOCTL_SET_PEER) failed with code %lu", GetLastError());
        return -1;
    }
    return 0;
}

int
dco_new_key(struct tuntap *tt, unsigned int peerid, ovpn_key_slot_t slot,
            struct key_state *ks, const char* ciphername)
{
    msg(D_DCO_DEBUG, "%s: slot %d, key-id %d, peer-id %d, cipher %s",
       __func__, slot, ks->key_id, peerid, ciphername);

    struct key_ctx_bi *key = &ks->crypto_options.key_ctx_bi;
    dco_check_key_ctx(key);

    const int nonce_len = 8;
    size_t key_len = cipher_kt_key_size(cipher_kt_get(ciphername));

    OVPN_CRYPTO_DATA crypto_data;
    ZeroMemory(&crypto_data, sizeof(crypto_data));

    crypto_data.CipherAlg = get_dco_cipher(ciphername);
    crypto_data.KeyId = ks->key_id;
    crypto_data.PeerId = peerid;
    crypto_data.KeySlot = slot;

    CopyMemory(crypto_data.Encrypt.Key, key->encrypt.aead_key, key_len);
    crypto_data.Encrypt.KeyLen = (char)key_len;
    CopyMemory(crypto_data.Encrypt.NonceTail, key->encrypt.implicit_iv, nonce_len);

    CopyMemory(crypto_data.Decrypt.Key, key->decrypt.aead_key, key_len);
    crypto_data.Decrypt.KeyLen = (char)key_len;
    CopyMemory(crypto_data.Decrypt.NonceTail, key->decrypt.implicit_iv, nonce_len);

    ASSERT(crypto_data.CipherAlg > 0);

    DWORD bytes_returned = 0;

    secure_memzero(key->encrypt.aead_key, sizeof (key->encrypt.aead_key));
    secure_memzero(key->decrypt.aead_key, sizeof (key->decrypt.aead_key));

    if (!DeviceIoControl(tt->hand, OVPN_IOCTL_NEW_KEY, &crypto_data, sizeof(crypto_data), NULL, 0,
                         &bytes_returned, NULL))
    {
        msg(M_ERR, "DeviceIoControl(OVPN_IOCTL_NEW_KEY) failed with code %lu", GetLastError());
        return -1;
    }
    return 0;
}
int
dco_del_key(struct tuntap *tt, unsigned int peerid, ovpn_key_slot_t slot)
{
    msg(D_DCO, "%s: peer-id %d, slot %d called but ignored", __func__, peerid, slot);
    /* FIXME: Implement in driver first */
    return 0;
}

int dco_swap_keys(struct tuntap *tt, unsigned int peer_id)
{
    msg(D_DCO_DEBUG, "%s: peer-id %d", __func__, peer_id);

    DWORD bytes_returned = 0;
    if (!DeviceIoControl(tt->hand, OVPN_IOCTL_SWAP_KEYS, NULL, 0, NULL, 0,
                         &bytes_returned, NULL))
    {
        msg(M_ERR, "DeviceIoControl(OVPN_IOCTL_SWAP_KEYS) failed with code %lu", GetLastError());
    }
    return 0;
}
#endif