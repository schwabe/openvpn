/*
 *  Interface to linux dco networking code
 *
 *  Copyright (C) 2020 Antonio Quartulli <a@unstable.cc>
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

#if defined(ENABLE_LINUXDCO)

#include "syshead.h"

#include "errlevel.h"
#include "buffer.h"
#include "networking.h"

#include "socket.h"
#include "tun.h"
#include "ssl.h"
#include "fdmisc.h"
#include "ssl_verify.h"

#include <linux/ovpn_dco.h>

#include <netlink/socket.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>


/* libnl < 3.5.0 does not set the NLA_F_NESTED on its own, therefore we
 * have to explicitly do it to prevent the kernel from failing upon
 * parsing of the message
 */
#define nla_nest_start(_msg, _type) \
	nla_nest_start(_msg, (_type) | NLA_F_NESTED)

static int ovpn_get_mcast_id(dco_context_t *dco);

void dco_check_key_ctx(const struct key_ctx_bi *key);

typedef int (*ovpn_nl_cb)(struct nl_msg *msg, void *arg);

int
resolve_ovpn_netlink_id(int msglevel)
{
    int ret;
    struct nl_sock* nl_sock = nl_socket_alloc();

    ret = genl_connect(nl_sock);
    if (ret)
    {
        msg(msglevel, "Cannot connect to generic netlink: %s",
                nl_geterror(ret));
        goto err_sock;
    }
    set_cloexec(nl_socket_get_fd(nl_sock));

    ret = genl_ctrl_resolve(nl_sock, OVPN_NL_NAME);
    if (ret < 0)
    {
        msg(msglevel, "Cannot find ovpn_dco netlink component: %s",
            nl_geterror(ret));
    }

err_sock:
    nl_socket_free(nl_sock);
    return ret;
}

static struct nl_msg *ovpn_dco_nlmsg_create(dco_context_t *dco,
                                            enum ovpn_nl_commands cmd)
{
    struct nl_msg *nl_msg = nlmsg_alloc();
    if (!nl_msg)
    {
        msg(M_ERR, "cannot allocate netlink message");
        return NULL;
    }

    genlmsg_put(nl_msg, 0, 0, dco->ovpn_dco_id, 0, 0, cmd, 0);
    NLA_PUT_U32(nl_msg, OVPN_ATTR_IFINDEX, dco->ifindex);

    return nl_msg;
    nla_put_failure:
    nlmsg_free(nl_msg);
    msg(M_INFO, "cannot put into netlink message");
    return NULL;
}

static int ovpn_nl_recvmsgs(dco_context_t *dco, const char *prefix)
{
    int ret = nl_recvmsgs(dco->nl_sock, dco->nl_cb);

    switch (ret) {
    case -NLE_INTR:
        msg(M_WARN, "%s: netlink received interrupt due to signal - ignoring", prefix);
        break;
    case -NLE_NOMEM:
        msg(M_ERR, "%s: netlink out of memory error", prefix);
        break;
    case -M_ERR:
        msg(M_WARN, "%s: netlink reports blocking read - aborting wait", prefix);
        break;
    case -NLE_NODEV:
        msg(M_ERR, "%s: netlink reports device not found:", prefix);
        break;
    case -NLE_OBJ_NOTFOUND:
        msg(M_INFO, "%s: netlink reports object not found, ovpn-dco unloaded?", prefix);
        break;
    default:
        if (ret)
        {
            msg(M_NONFATAL|M_ERRNO, "%s: netlink reports error (%d): %s", prefix, ret, nl_geterror(-ret));
        }
        break;
    }

    return ret;
}

/**
 * Send a preprared netlink message and registers cb as callback if non-null.
 *
 * The method will also free nl_msg
 * @param dco       The dco context to use
 * @param nl_msg    the message to use
 * @param cb        An optional callback if the caller expects an answers\
 * @param prefix    A prefix to report in the error message to give the user context
 * @return          status of sending the message
 */
static int
ovpn_nl_msg_send(dco_context_t *dco, struct nl_msg *nl_msg, ovpn_nl_cb cb,
                 const char* prefix)
{
    dco->status = 1;

    if (cb)
    {
        nl_cb_set(dco->nl_cb, NL_CB_VALID, NL_CB_CUSTOM, cb, dco);
    }
    else
    {
        nl_cb_set(dco->nl_cb, NL_CB_VALID, NL_CB_CUSTOM, NULL, dco);
    }

    nl_send_auto(dco->nl_sock, nl_msg);

    while (dco->status == 1)
    {
        ovpn_nl_recvmsgs(dco, prefix);
    }

    if (dco->status < 0)
    {
        msg(M_INFO, "%s: failed to send netlink message: %s (%d)",
            prefix, strerror(-dco->status), dco->status);
    }

    nlmsg_free(nl_msg);
    return dco->status;
}


static bool isAddrDefined(struct sockaddr *sockaddr)
{
    switch (sockaddr->sa_family) {
    case AF_INET:
        return ((struct sockaddr_in *)sockaddr)->sin_addr.s_addr != INADDR_ANY;
    case AF_INET6:
        return memcmp(&((struct sockaddr_in6 *)sockaddr)->sin6_addr,
                      &in6addr_any, sizeof(in6addr_any));
    default:
        return false;
    }
}

struct sockaddr *
mapped_v4_to_v6(struct sockaddr *sock, struct gc_arena *gc)
{
    struct sockaddr_in6 *sock6 = ((struct sockaddr_in6 *)sock);
    if (sock->sa_family == AF_INET6 &&
        memcmp(&sock6->sin6_addr, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff", 12)==0)
    {

        struct sockaddr_in* sock4;
        ALLOC_OBJ_CLEAR_GC(sock4, struct sockaddr_in, gc);
        memcpy (&sock4->sin_addr, sock6->sin6_addr.s6_addr +12, 4);
        sock4->sin_port = sock6->sin6_port;
        sock4->sin_family = AF_INET;
        return (struct sockaddr *) sock4;
    }
    return sock;
}

int dco_new_peer(struct tuntap *tt, unsigned int peerid, int sd,
                 struct sockaddr *localaddr, struct sockaddr *remoteaddr,
                 struct in_addr *remote_in4, struct in6_addr *remote_in6)
{
    msg(D_DCO_DEBUG, "%s: peer-id %d, fd %d", __func__, peerid, sd);

    struct gc_arena gc = gc_new();

    struct nl_msg *nl_msg = ovpn_dco_nlmsg_create(&tt->dco, OVPN_CMD_NEW_PEER);

    struct nlattr *attr = nla_nest_start(nl_msg, OVPN_ATTR_NEW_PEER);

    NLA_PUT_U32(nl_msg, OVPN_NEW_PEER_ATTR_PEER_ID, peerid);
    NLA_PUT_U32(nl_msg, OVPN_NEW_PEER_ATTR_SOCKET, sd);

    /* Set the remote endpoint if defined (for UDP) */
    if (remoteaddr)
    {
        remoteaddr = mapped_v4_to_v6(remoteaddr, &gc);
        int alen = af_addr_size(remoteaddr->sa_family);

        NLA_PUT(nl_msg, OVPN_NEW_PEER_ATTR_SOCKADDR_REMOTE, alen, remoteaddr);
    }

    if (localaddr)
    {
        localaddr = mapped_v4_to_v6(localaddr, &gc);
        if (localaddr->sa_family == AF_INET)
        {
            NLA_PUT(nl_msg, OVPN_NEW_PEER_ATTR_LOCAL_IP, sizeof(struct in_addr),
                    &((struct sockaddr_in *)localaddr)->sin_addr);
        }
        else if (localaddr->sa_family == AF_INET6)
        {
            NLA_PUT(nl_msg, OVPN_NEW_PEER_ATTR_LOCAL_IP, sizeof(struct in6_addr),
                    &((struct sockaddr_in6 *)localaddr)->sin6_addr);
        }
    }

    /* Set the primary VPN IP addresses of the peer */
    if (remote_in4)
    {
        NLA_PUT_U32(nl_msg, OVPN_NEW_PEER_ATTR_IPV4, remote_in4->s_addr);
    }
    if (remote_in6)
    {
        NLA_PUT(nl_msg, OVPN_NEW_PEER_ATTR_IPV6, sizeof(struct in6_addr),
                remote_in6);
    }
    nla_nest_end(nl_msg, attr);


    int ret = ovpn_nl_msg_send(&tt->dco, nl_msg, NULL, __func__);

    gc_free(&gc);

    return ret;

nla_put_failure:
    return -1;

}

static int
ovpn_nl_cb_finish(struct nl_msg (*msg)__attribute__((unused)), void *arg)
{
    int *status = arg;

    *status = 0;
    return NL_SKIP;
}

static int
ovpn_nl_cb_error(struct sockaddr_nl (*nla)__attribute__((unused)),
                 struct nlmsgerr *err, void *arg)
{
    struct nlmsghdr *nlh = (struct nlmsghdr *)err - 1;
    struct nlattr *tb_msg[NLMSGERR_ATTR_MAX + 1];
    int len = nlh->nlmsg_len;
    struct nlattr *attrs;
    int *ret = arg;
    int ack_len = sizeof(*nlh) + sizeof(int) + sizeof(*nlh);

    *ret = err->error;

    if (!(nlh->nlmsg_flags & NLM_F_ACK_TLVS))
        return NL_STOP;

    if (!(nlh->nlmsg_flags & NLM_F_CAPPED))
        ack_len += err->msg.nlmsg_len - sizeof(*nlh);

    if (len <= ack_len)
        return NL_STOP;

    attrs = (void *)((unsigned char *)nlh + ack_len);
    len -= ack_len;

    nla_parse(tb_msg, NLMSGERR_ATTR_MAX, attrs, len, NULL);
    if (tb_msg[NLMSGERR_ATTR_MSG]) {
        len = strnlen((char *)nla_data(tb_msg[NLMSGERR_ATTR_MSG]),
                      nla_len(tb_msg[NLMSGERR_ATTR_MSG]));
        msg(M_WARN, "kernel error: %*s\n", len,
            (char *)nla_data(tb_msg[NLMSGERR_ATTR_MSG]));
    }

    return NL_STOP;
}

static void
ovpn_dco_init_netlink(dco_context_t *dco)
{
    dco->ovpn_dco_id = resolve_ovpn_netlink_id(M_ERR);

    dco->nl_sock = nl_socket_alloc();


    if (!dco->nl_sock)
    {
        msg(M_ERR, "Cannot create netlink socket");
    }

    /* TODO: Why are we setting this buffer size? */
    nl_socket_set_buffer_size(dco->nl_sock, 8192, 8192);

    int ret = genl_connect(dco->nl_sock);
    if (ret)
    {
        msg(M_ERR, "Cannot connect to generic netlink: %s",
            nl_geterror(ret));
    }

    set_cloexec(nl_socket_get_fd(dco->nl_sock));

    dco->nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!dco->nl_cb)
    {
        msg(M_ERR, "failed to allocate netlink callback");
    }

    nl_socket_set_cb(dco->nl_sock, dco->nl_cb);

    nl_cb_err(dco->nl_cb, NL_CB_CUSTOM, ovpn_nl_cb_error, &dco->status);
    nl_cb_set(dco->nl_cb, NL_CB_FINISH, NL_CB_CUSTOM, ovpn_nl_cb_finish,
              &dco->status);
    nl_cb_set(dco->nl_cb, NL_CB_ACK, NL_CB_CUSTOM, ovpn_nl_cb_finish,
              &dco->status);

    /* The async PACKET messages confuse libnl and it will drop them with
     * wrong sequence numbers (NLE_SEQ_MISMATCH), so disable libnl's sequence
     * number check */
    nl_socket_disable_seq_check(dco->nl_sock);
}

static void
ovpn_dco_uninit_netlink(dco_context_t *dco)
{
    nl_socket_free(dco->nl_sock);
    dco->nl_sock = NULL;

    /* Decrease reference count */
    nl_cb_put(dco->nl_cb);

    memset(dco, 0, sizeof(*dco));
}

static void ovpn_dco_register(dco_context_t *dco)
{
    msg(D_DCO_DEBUG, __func__);
    ovpn_get_mcast_id(dco);

    if (dco->ovpn_dco_mcast_id < 0)
    {
        msg(M_ERR, "cannot get mcast group: %s",  nl_geterror(dco->ovpn_dco_mcast_id));
    }

    /* Register for Ovpn dco specific messages */
    int ret = nl_socket_add_membership(dco->nl_sock, dco->ovpn_dco_mcast_id);
    if (ret)
    {
        msg(M_ERR, "%s: failed to join groups: %d", __func__, ret);
    }

    struct nl_msg *nl_msg = ovpn_dco_nlmsg_create(dco, OVPN_CMD_REGISTER_PACKET);
    ovpn_nl_msg_send(dco, nl_msg, NULL, __func__);
}

void
open_tun_dco(struct tuntap *tt, const char* dev)
{
    msg(D_DCO_DEBUG, __func__);
    ASSERT(tt->type == DEV_TYPE_TUN);

    ovpn_dco_init_netlink(&tt->dco);

    char if_name[IFNAMSIZ];

    if (!strcmp(dev, "tun"))
    {
        /* If no specific name has been requested use an auto-assigned name */
        dev = NULL;
    }

    tt->dco.ifindex = net_iface_new(dev, "ovpn-dco");

    if(!if_indextoname(tt->dco.ifindex, if_name))
    {
        msg(M_ERR|M_ERRNO, "Cannot resolve interface name for dco interface: ");
    }
    tt->actual_name = string_alloc(if_name, NULL);
    uint8_t *dcobuf = malloc(65536);
    buf_set_write(&tt->dco.dco_packet_in, dcobuf, 65536);
    tt->dco.dco_meesage_peer_id = -1;

    ovpn_dco_register(&tt->dco);
}

void
close_tun_dco(struct tuntap *tt)
{
    msg(D_DCO_DEBUG, __func__);

    net_iface_del_index(tt->dco.ifindex);
    ovpn_dco_uninit_netlink(&tt->dco);
    free(tt->dco.dco_packet_in.data);
}

int dco_swap_keys(struct tuntap *tt, unsigned int peerid)
{
    msg(D_DCO_DEBUG, "%s: peer-id %d", __func__, peerid);

    struct nl_msg *nl_msg = ovpn_dco_nlmsg_create(&tt->dco, OVPN_CMD_SWAP_KEYS);

    if (!nl_msg)
        return -ENOMEM;

    struct nlattr *attr = nla_nest_start(nl_msg, OVPN_ATTR_SWAP_KEYS);
    NLA_PUT_U32(nl_msg, OVPN_SWAP_KEYS_ATTR_PEER_ID, peerid);
    nla_nest_end(nl_msg, attr);

    int ret = ovpn_nl_msg_send(&tt->dco, nl_msg, NULL, __func__);

nla_put_failure:
    return ret;
}


int dco_del_peer(struct tuntap *tt, unsigned int peerid)
{
    msg(D_DCO_DEBUG, "%s: peer-id %d", __func__, peerid);

    struct nl_msg *nl_msg = ovpn_dco_nlmsg_create(&tt->dco, OVPN_CMD_DEL_PEER);

    if (!nl_msg)
        return -ENOMEM;

    struct nlattr *attr = nla_nest_start(nl_msg, OVPN_ATTR_DEL_PEER);
    NLA_PUT_U32(nl_msg, OVPN_DEL_PEER_ATTR_PEER_ID, peerid);
    nla_nest_end(nl_msg, attr);

    int ret = ovpn_nl_msg_send(&tt->dco, nl_msg, NULL, __func__);

    nla_put_failure:
    return ret;
}


int
dco_del_key(struct tuntap *tt, unsigned int peerid, ovpn_key_slot_t slot)
{
    msg(D_DCO_DEBUG, "%s: peer-id %d, slot %d", __func__, peerid, slot);

    struct nl_msg *nl_msg = ovpn_dco_nlmsg_create(&tt->dco, OVPN_CMD_DEL_KEY);

    if (!nl_msg)
        return -ENOMEM;

    struct nlattr *attr = nla_nest_start(nl_msg, OVPN_ATTR_DEL_KEY);
    NLA_PUT_U32(nl_msg, OVPN_DEL_KEY_ATTR_PEER_ID, peerid);
    NLA_PUT_U8(nl_msg, OVPN_DEL_KEY_ATTR_KEY_SLOT, slot);
    nla_nest_end(nl_msg, attr);

    int ret = ovpn_nl_msg_send(&tt->dco, nl_msg, NULL, __func__);

    nla_put_failure:
    return ret;
}

int
dco_new_key(struct tuntap *tt, unsigned int peerid, ovpn_key_slot_t slot,
             struct key_state *ks, const char* ciphername)
{
    msg(D_DCO_DEBUG, "%s: slot %d, key-id %d, peer-id %d, cipher %s",
        __func__, slot, ks->key_id, peerid, ciphername);
    const int nonce_len = 8;

    struct key_ctx_bi *key = &ks->crypto_options.key_ctx_bi;

    dco_check_key_ctx(key);

    struct nl_msg *nl_msg = ovpn_dco_nlmsg_create(&tt->dco, OVPN_CMD_NEW_KEY);

    if (!nl_msg)
        return -ENOMEM;

    int dco_cipher = get_dco_cipher(ciphername);
    ASSERT(dco_cipher >= 0);


    struct nlattr *attr = nla_nest_start(nl_msg, OVPN_ATTR_NEW_KEY);

    NLA_PUT_U32(nl_msg, OVPN_NEW_KEY_ATTR_PEER_ID, peerid);
    NLA_PUT_U8(nl_msg, OVPN_NEW_KEY_ATTR_KEY_SLOT, slot);
    NLA_PUT_U8(nl_msg, OVPN_NEW_KEY_ATTR_KEY_ID, ks->key_id);

    NLA_PUT_U16(nl_msg, OVPN_NEW_KEY_ATTR_CIPHER_ALG, dco_cipher);

    if (dco_cipher != OVPN_CIPHER_ALG_NONE)
    {
        size_t key_len = cipher_kt_key_size(ciphername);
        struct nlattr *key_enc = nla_nest_start(nl_msg, OVPN_NEW_KEY_ATTR_ENCRYPT_KEY);
        NLA_PUT(nl_msg, OVPN_KEY_DIR_ATTR_CIPHER_KEY, key_len, key->encrypt.aead_key);
        NLA_PUT(nl_msg, OVPN_KEY_DIR_ATTR_NONCE_TAIL, nonce_len,
                key->encrypt.implicit_iv);
        nla_nest_end(nl_msg, key_enc);

        struct nlattr *key_dec = nla_nest_start(nl_msg, OVPN_NEW_KEY_ATTR_DECRYPT_KEY);
        NLA_PUT(nl_msg, OVPN_KEY_DIR_ATTR_CIPHER_KEY, key_len, key->decrypt.aead_key);
        NLA_PUT(nl_msg, OVPN_KEY_DIR_ATTR_NONCE_TAIL, nonce_len,
                key->decrypt.implicit_iv);
        nla_nest_end(nl_msg, key_dec);
    }
    else
    {
        /* Check that --auth is disabled. Normally, we would catch this
         * inconsistency earlier but since the "none" is only for debug and
         * requires manual editing of DCO_SUPPORTED_CIPHERS, it should be fine
         * to abort here */
        if (key->encrypt.hmac != NULL)
        {
            msg(M_FATAL, "FATAL: DCO with cipher none requires --auth none");
        }
        /* ovpn-dco needs empty encrypt/decrypt keys with cipher none */
        struct nlattr *key_enc = nla_nest_start(nl_msg, OVPN_NEW_KEY_ATTR_ENCRYPT_KEY);
        NLA_PUT(nl_msg, OVPN_KEY_DIR_ATTR_CIPHER_KEY, 16, key->encrypt.aead_key);
        nla_nest_end(nl_msg, key_enc);

        struct nlattr *key_dec = nla_nest_start(nl_msg, OVPN_NEW_KEY_ATTR_DECRYPT_KEY);
        NLA_PUT(nl_msg, OVPN_KEY_DIR_ATTR_CIPHER_KEY, 16, key->decrypt.aead_key);
        nla_nest_end(nl_msg, key_dec);
    }

    secure_memzero(key->encrypt.aead_key, sizeof (key->encrypt.aead_key));
    secure_memzero(key->decrypt.aead_key, sizeof (key->decrypt.aead_key));

    nla_nest_end(nl_msg, attr);

    int ret = ovpn_nl_msg_send(&tt->dco, nl_msg, NULL, __func__);
nla_put_failure:
    return ret;
}

int ovpn_set_peer(struct tuntap *tt, unsigned int peerid,
                  unsigned int keepalive_interval,
                  unsigned int keepalive_timeout)
{
    msg(D_DCO_DEBUG, "%s: peer-id %d, keepalive %d/%d", __func__, peerid,
                     keepalive_interval, keepalive_timeout);
    int ret = -1;

    struct nl_msg *nl_msg = ovpn_dco_nlmsg_create(&tt->dco, OVPN_CMD_SET_PEER);

    if (!nl_msg)
    {
        return -ENOMEM;
    }

    struct nlattr *attr = nla_nest_start(nl_msg, OVPN_ATTR_SET_PEER);

    NLA_PUT_U32(nl_msg, OVPN_SET_PEER_ATTR_PEER_ID, peerid);
    NLA_PUT_U32(nl_msg, OVPN_SET_PEER_ATTR_KEEPALIVE_INTERVAL, keepalive_interval);
    NLA_PUT_U32(nl_msg, OVPN_SET_PEER_ATTR_KEEPALIVE_TIMEOUT, keepalive_timeout);

    nla_nest_end(nl_msg, attr);

    ret = ovpn_nl_msg_send(&tt->dco, nl_msg, NULL, __func__);
    return ret;
nla_put_failure:
    nlmsg_free(nl_msg);
    return ret;
}

static int mcast_family_handler(struct nl_msg *msg, void *arg)
{
    dco_context_t *dco = arg;
    struct nlattr *tb[CTRL_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

    nla_parse(tb, CTRL_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[CTRL_ATTR_MCAST_GROUPS])
        return NL_SKIP;

    struct nlattr *mcgrp;
    int rem_mcgrp;
    nla_for_each_nested(mcgrp, tb[CTRL_ATTR_MCAST_GROUPS], rem_mcgrp) {
        struct nlattr *tb_mcgrp[CTRL_ATTR_MCAST_GRP_MAX + 1];

        nla_parse(tb_mcgrp, CTRL_ATTR_MCAST_GRP_MAX,
                  nla_data(mcgrp), nla_len(mcgrp), NULL);

        if (!tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME] ||
            !tb_mcgrp[CTRL_ATTR_MCAST_GRP_ID])
        {
            continue;
        }

        if (strncmp(nla_data(tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME]),
                    OVPN_NL_MULTICAST_GROUP_PEERS,
                    nla_len(tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME])) != 0)
        {
            continue;
        }
        dco->ovpn_dco_mcast_id = nla_get_u32(tb_mcgrp[CTRL_ATTR_MCAST_GRP_ID]);
        break;
    }

    return NL_SKIP;
}
/**
 * Lookup the multicast id for OpenVPN. This method and its help method currently
 * hardcode the lookup to OVPN_NL_NAME and OVPN_NL_MULTICAST_GROUP_PEERS but
 * extended in the future if we need to lookup more than one mcast id.
  */
static int
ovpn_get_mcast_id(dco_context_t *dco)
{
    dco->ovpn_dco_mcast_id = -ENOENT;

    /* Even though 'nlctrl' is a constant, there seem to be no library
     * provided define for it */
    int ctrlid = genl_ctrl_resolve(dco->nl_sock, "nlctrl");

    struct nl_msg *nl_msg = nlmsg_alloc();
    if (!nl_msg)
        return -ENOMEM;

    genlmsg_put(nl_msg, 0, 0, ctrlid, 0, 0, CTRL_CMD_GETFAMILY, 0);

    int ret = -ENOBUFS;
    NLA_PUT_STRING(nl_msg, CTRL_ATTR_FAMILY_NAME, OVPN_NL_NAME);



    ovpn_nl_msg_send(dco, nl_msg, mcast_family_handler, __func__);

    if (ret < 0)
    {
        goto nla_put_failure;
    }

    nla_put_failure:
    return ret;
}

static int ovpn_handle_msg(struct nl_msg *msg, void *arg)
{
    dco_context_t *dco = arg;

    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *attrs[OVPN_ATTR_MAX + 1];
    struct nlmsghdr *nlh = nlmsg_hdr(msg);

    if (!genlmsg_valid_hdr(nlh, 0)) {
        msg(D_DCO, "ovpn-dco: invalid header");
        return NL_SKIP;
    }

    if (nla_parse(attrs, OVPN_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
                  genlmsg_attrlen(gnlh, 0), NULL)) {
        msg(D_DCO, "received bogus data from ovpn-dco");
        return NL_SKIP;
    }

    if (!attrs[OVPN_ATTR_IFINDEX])
    {
        msg(D_DCO, "ovpn-dco: Received message without ifindex");
        return NL_SKIP;
    }

    uint32_t ifindex = nla_get_u32(attrs[OVPN_ATTR_IFINDEX]);
    if (ifindex != dco->ifindex)
    {
        msg(D_DCO, "ovpn-dco: received message type %d with mismatched ifindex %d\n",
            gnlh->cmd, ifindex);
        return NL_SKIP;
    }

    switch (gnlh->cmd) {
    case OVPN_CMD_DEL_PEER:
    {
        if (!attrs[OVPN_ATTR_DEL_PEER])
        {
            msg(D_DCO, "ovpn-dco: no attributes in OVPN_DEL_PEER message");
            return NL_SKIP;
        }
        struct nlattr *dp_attrs[OVPN_DEL_PEER_ATTR_MAX + 1];
        if (nla_parse_nested(dp_attrs, OVPN_DEL_PEER_ATTR_MAX, attrs[OVPN_ATTR_DEL_PEER], NULL))
        {
            msg(D_DCO, "received bogus del peer packet data from ovpn-dco");
            return NL_SKIP;
        }

        if (!dp_attrs[OVPN_DEL_PEER_ATTR_REASON])
        {
            msg(D_DCO, "ovpn-dco: no reason in DEL_PEER message");
            return NL_SKIP;
        }
        if (!dp_attrs[OVPN_DEL_PEER_ATTR_PEER_ID])
        {
            msg(D_DCO, "ovpn-dco: no peer-id in DEL_PEER message");
            return NL_SKIP;
        }
        int reason = nla_get_u8(dp_attrs[OVPN_DEL_PEER_ATTR_REASON]);
        unsigned int peerid = nla_get_u32(dp_attrs[OVPN_DEL_PEER_ATTR_PEER_ID]);

        msg(D_DCO_DEBUG, "ovpn-dco: received CMD_DEL_PEER, ifindex: %d, peer-id %d, reason: %d",
            ifindex, peerid, reason);
        dco->dco_meesage_peer_id = peerid;
        dco->dco_del_peer_reason = reason;
        dco->dco_message_type = OVPN_CMD_DEL_PEER;

        break;
    }
    case OVPN_CMD_PACKET:
    {
        if (!attrs[OVPN_ATTR_PACKET])
        {
            msg(D_DCO, "ovpn-dco: no packet in OVPN_CMD_PACKET message");
            return NL_SKIP;
        }
        struct nlattr *pkt_attrs[OVPN_PACKET_ATTR_MAX + 1];

        if (nla_parse_nested(pkt_attrs, OVPN_PACKET_ATTR_MAX, attrs[OVPN_ATTR_PACKET], NULL))
        {
            msg(D_DCO, "received bogus cmd packet data from ovpn-dco");
            return NL_SKIP;
        }
        if (!pkt_attrs[OVPN_PACKET_ATTR_PEER_ID])
        {
            msg(D_DCO, "ovpn-dco: Received OVPN_CMD_PACKET message without peer id");
            return NL_SKIP;
        }
        if (!pkt_attrs[OVPN_PACKET_ATTR_PACKET])
        {
            msg(D_DCO, "ovpn-dco: Received OVPN_CMD_PACKET message without packet");
            return NL_SKIP;
        }

        unsigned int peerid = nla_get_u32(pkt_attrs[OVPN_PACKET_ATTR_PEER_ID]);

        uint8_t *data = nla_data(pkt_attrs[OVPN_PACKET_ATTR_PACKET]);
        int len = nla_len(pkt_attrs[OVPN_PACKET_ATTR_PACKET]);

        msg(D_DCO_DEBUG, "ovpn-dco: received OVPN_PACKET_ATTR_PACKET, ifindex: %d peer-id: %d, len %d",
            ifindex, peerid, len);
        if (BLEN(&dco->dco_packet_in) > 0)
        {
            msg(D_DCO, "DCO packet buffer still full?!");
            return NL_SKIP;
        }
        buf_init(&dco->dco_packet_in, 0);
        buf_write(&dco->dco_packet_in, data, len);
        dco->dco_meesage_peer_id = peerid;
        dco->dco_message_type = OVPN_CMD_PACKET;
        break;
    }
    default:
        msg(D_DCO, "ovpn-dco: received unknown command: %d", gnlh->cmd);
        dco->dco_message_type = 0;
        return NL_SKIP;
    }

    return NL_OK;
}

int
ovpn_do_read_dco(struct dco_context *dco)
{
    msg(D_DCO_DEBUG, __func__);
    nl_cb_set(dco->nl_cb, NL_CB_VALID, NL_CB_CUSTOM, ovpn_handle_msg, dco);

    return ovpn_nl_recvmsgs(dco, __func__);
}

int
ovpn_do_write_dco(dco_context_t *dco, int peer_id, struct buffer *buf)
{
    packet_size_type len = BLEN(buf);
    dmsg(D_STREAM_DEBUG, "DCO: WRITE %d offset=%d", (int)len, buf->offset);

    msg(D_DCO_DEBUG, "%s: peer-id %d, len=%d", __func__, peer_id, len);

    struct nl_msg *nl_msg = ovpn_dco_nlmsg_create(dco, OVPN_CMD_PACKET);

    if (!nl_msg)
        return -ENOMEM;

    struct nlattr *attr = nla_nest_start(nl_msg, OVPN_ATTR_PACKET);
    NLA_PUT_U32(nl_msg, OVPN_PACKET_ATTR_PEER_ID, peer_id);
    NLA_PUT(nl_msg, OVPN_PACKET_ATTR_PACKET, len, BSTR(buf));
    nla_nest_end(nl_msg, attr);

    int ret = ovpn_nl_msg_send(dco, nl_msg, NULL, __func__);

    nla_put_failure:
    if (ret)
    {
        return ret;
    }
    return len;
}


#endif
