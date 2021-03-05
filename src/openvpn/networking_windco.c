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


#include <Winsock2.h>
#include <Ws2tcpip.h>

const char* dco_dev = "\\\\.\\ovpn-dco";

static HANDLE create_dco_handle(void)
{

    HANDLE h = CreateFileA(dco_dev, GENERIC_READ | GENERIC_WRITE,
                                0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, NULL);
    if (h == INVALID_HANDLE_VALUE)
    {
        msg(M_ERR, "CreateFileA(%s) failed with code %d ", dco_dev, GetLastError());
    }
    return h;
}

void open_tun_dco(struct tuntap *tt, const char* dev)
{
    if (tt->dco_ctx.h)
    {
        return;
    }
    tt->dco_ctx.h = create_dco_handle();
    tt->actual_name = string_alloc("win-dco-name-fixme", NULL);
}

socket_descriptor_t
dco_create_socket(struct addrinfo *remoteaddr, bool bind_local,
                  struct addrinfo *bind)
{
    msg(D_DCO_DEBUG, "%s: peer-id %d, fd %d", __func__);

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

    HANDLE h = create_dco_handle();

    if (!DeviceIoControl(h, OVPN_IOCTL_NEW_PEER, &peer, sizeof(peer), NULL, 0, NULL, NULL))
    {
        msg(M_ERR, "DeviceIoControl(OVPN_IOCTL_NEW_PEER) failed with code %d", GetLastError());
        return INVALID_SOCKET;
    }
    return h;
}

int dco_new_peer(dco_context_t *dco, unsigned int peerid, int sd,
                 struct sockaddr *remoteaddr, struct in_addr *remote_in4,
                 struct in6_addr *remote_in6) {
    msg(D_DCO_DEBUG, "%s: peer-id %d, fd %d", __func__, peerid, sd);
    return 0;
}

int ovpn_set_peer(struct dco_context *dco, unsigned int peerid,
                  unsigned int keepalive_interval,
                  unsigned int keepalive_timeout)
{
    msg(D_DCO_DEBUG, "%s: peer-id %d, keepalive %d/%d", __func__, peerid,
        keepalive_interval, keepalive_timeout);

    OVPN_SET_PEER peer;

    peer.KeepaliveInterval =  keepalive_interval;
    peer.KeepaliveTimeout = keepalive_timeout;

    DWORD bytes_returned = 0;
    if (!DeviceIoControl(&dco->h, OVPN_IOCTL_SET_PEER, &peer, sizeof(peer), NULL, 0, &bytes_returned, NULL)) {
        msg(M_WARN, "DeviceIoControl(OVPN_IOCTL_SET_PEER) failed with code %d", GetLastError());
        return -1;
    }
    return 0;
}

int
dco_new_key(dco_context_t *dco, unsigned int peerid, enum ovpn_key_slot slot,
            struct key_state *ks, const char* ciphername)
{
    msg(D_DCO_DEBUG, "%s: slot %d, key-id %d, peer-id %d, cipher %s",
       __func__, slot, ks->key_id, peerid, ciphername);

    struct key_ctx_bi *key = &ks->crypto_options.key_ctx_bi;
    ASSERT(key->initialized);

    const int nonce_len = 8;
    int nonce_offset = cipher_ctx_iv_length(key->decrypt.cipher) - nonce_len;
    size_t key_len = cipher_kt_key_size(cipher_kt_get(ciphername));

    OVPN_CRYPTO_DATA crypto_data;
    ZeroMemory(&crypto_data, sizeof(crypto_data));

    crypto_data.CipherAlg = get_dco_cipher(ciphername);
    crypto_data.KeyId = ks->key_id;
    crypto_data.PeerId = peerid;
    crypto_data.KeySlot = slot;

    CopyMemory(crypto_data.Encrypt.Key, key->encrypt.aead_key, key_len);
    crypto_data.Encrypt.KeyLen = (char)key_len;
    CopyMemory(crypto_data.Encrypt.NonceTail, key->encrypt.implicit_iv + nonce_offset, nonce_len);

    CopyMemory(crypto_data.Decrypt.Key, key->decrypt.aead_key, key_len);
    crypto_data.Decrypt.KeyLen = (char)key_len;
    CopyMemory(crypto_data.Decrypt.NonceTail, key->decrypt.implicit_iv + nonce_offset, nonce_len);

    ASSERT(crypto_data.CipherAlg > 0);

    DWORD bytes_returned = 0;
    if (!DeviceIoControl(dco->h, OVPN_IOCTL_NEW_KEY, &crypto_data, sizeof(crypto_data), NULL, 0,
                         &bytes_returned, NULL))
    {
        msg(M_ERR, "DeviceIoControl(OVPN_IOCTL_NEW_KEY) failed with code %d", GetLastError());
        return -1;
    }
    return 0;
}
int
dco_del_key(dco_context_t *dco, unsigned int peerid, enum ovpn_key_slot slot)
{
    msg(D_DCO_DEBUG, "%s: peer-id %d, slot %d", __func__, peerid, slot);
    /* FIXME: IMplement in driver first */
    return 0;
}

int dco_swap_keys(dco_context_t *dco, unsigned int peer_id)
{
    msg(D_DCO_DEBUG, "%s: peer-id %d", __func__, peer_id);

    DWORD bytes_returned = 0;
    if (!DeviceIoControl(dco->h, OVPN_IOCTL_SWAP_KEYS, NULL, 0, NULL, 0,
                         &bytes_returned, NULL))
    {
        msg(M_ERR, "DeviceIoControl(OVPN_IOCTL_SWAP_KEYS) failed with code %d", GetLastError());
    }
    return 0;
}

int ovpn_do_write_dco(dco_context_t *dco, int peer_id, struct buffer *buf)
{
    msg(D_DCO_DEBUG, "%s: peer-id %d", __func__, peer_id);
    return BLEN(buf);
}

#endif