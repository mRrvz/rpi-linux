// SPDX-License-Identifier: GPL-2.0-or-later

#include <net/sock.h>
#include <net/protocol.h>
#include <net/inet_common.h>
#include <net/inet_hashtables.h>
#include <net/encrypted.h>
#include <net/ip.h>
#include <crypto/skcipher.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>

#define CIPHER_ALGO "aes"

static inline void encrypted_close(struct sock *sk, long timeout)
{
	sk_common_release(sk);
}

static int encrypted_disconnect(struct sock *sk, int flags)
{
	struct inet_sock *inet = inet_sk(sk);

	sk->sk_state = TCP_CLOSE;
	inet->inet_daddr = 0;
	inet->inet_dport = 0;

	sk_dst_reset(sk);

	return 0;
}

static int encrypted_sk_init(struct sock *sk)
{
	(void)sk;

	return 0;
}

static void encrypted_sk_destroy(struct sock *sk)
{
	release_sock(sk);
}

static int encrypt_msghdr_data(struct msghdr *msg, size_t size)
{
	struct crypto_skcipher *skcipher = NULL;
	struct skcipher_request *req = NULL;
	char key[] = "0123456789ABCDEF";
	char iv[] = "1234567890ABCDEF";
	char *buffer, *out;
	int ret = 0;

	buffer = kmalloc(size, GFP_KERNEL);
	if (unlikely(!buffer))
		return -ENOMEM;

	out = kmalloc(size, GFP_KERNEL);
	if (unlikely(!buffer)) {
		ret = -ENOMEM;
		goto out;
	}

	skcipher = crypto_alloc_skcipher(CIPHER_ALGO, 0, 0);
	if (IS_ERR(skcipher)) {
		ret = -ENOMEM;
		goto out;
	}

	ret = crypto_skcipher_setkey(skcipher, key, sizeof(key));
	if (ret)
		goto out;

	req = skcipher_request_alloc(skcipher, GFP_KERNEL);
	if (!req) {
		ret = -ENOMEM;
		goto out;
	}

	memcpy_from_msg(buffer, msg, size);

	sg_init_one(req->dst, out, sizeof(out));
	sg_init_one(req->src, buffer, sizeof(buffer));
	skcipher_request_set_crypt(req, req->src, req->dst, sizeof(buffer), iv);

	ret = crypto_skcipher_encrypt(req);
	if (ret)
		goto out;

	memcpy_to_msg(msg, out, req->cryptlen);

out:
	if (req)
		skcipher_request_free(req);

	if (skcipher)
		crypto_free_skcipher(skcipher);

	kfree(out);
	kfree(buffer);

	return ret;
}

static int decrypt_msghdr_data(struct msghdr *msg, size_t size)
{
	struct crypto_skcipher *skcipher = NULL;
	struct skcipher_request *req = NULL;
	char key[] = "0123456789ABCDEF";
	char iv[] = "1234567890ABCDEF";
	char *buffer, *out;
	int ret = 0;

	buffer = kmalloc(size, GFP_KERNEL);
	if (unlikely(!buffer))
		return -ENOMEM;

	out = kmalloc(size, GFP_KERNEL);
	if (unlikely(!buffer)) {
		ret = -ENOMEM;
		goto out;
	}

	memcpy_from_msg(buffer, msg, size);

	skcipher = crypto_alloc_skcipher(CIPHER_ALGO, 0, 0);
	if (IS_ERR(skcipher)) {
		ret = -ENOMEM;
		goto out;
	}

	ret = crypto_skcipher_setkey(skcipher, key, sizeof(key));
	if (ret)
		goto out;

	req = skcipher_request_alloc(skcipher, GFP_KERNEL);
	if (!req) {
		ret = -ENOMEM;
		goto out;
	}

	memcpy_from_msg(buffer, msg, size);

	sg_init_one(req->dst, out, sizeof(out));
	sg_init_one(req->src, buffer, sizeof(buffer));
	skcipher_request_set_crypt(req, req->src, req->dst, sizeof(buffer), iv);

	ret = crypto_skcipher_encrypt(req);
	if (ret)
		goto out;

	memcpy_to_msg(msg, out, size);

out:
	if (req)
		skcipher_request_free(req);

	if (skcipher)
		crypto_free_skcipher(skcipher);

	kfree(out);
	kfree(buffer);

	return ret;
}

static int encrypted_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct net *net = sock_net(sk);
	DECLARE_SOCKADDR(struct sockaddr_in *, usin, msg->msg_name);
	struct ipcm_cookie ipc;
	struct flowi4 *fl4;
	struct flowi4 fl4_stack;
	struct rtable *rt = NULL;
	__be32 daddr, faddr, saddr;
	__u8 flow_flags;
	__be16 dport;
	u8 tos, scope;
	size_t ulen = len;
	int err;

	ulen += sizeof(encrypted_hdr);

	if (usin) {
		daddr = usin->sin_addr.s_addr;
		dport = usin->sin_port;

		if (!dport)
			return -EINVAL;
	} 

	ipcm_init_sk(&ipc, inet);

	saddr = ipc.addr;
	ipc.addr = faddr = daddr;

	if (ipc.opt && ipc.opt->opt.srr)
		faddr = ipc.opt->opt.faddr;

	tos = get_rttos(&ipc, inet);
	scope = ip_sendmsg_scope(inet, &ipc, msg);

	if (ipv4_is_multicast(daddr)) {
		if (!ipc.oif || netif_index_is_l3_master(sock_net(sk), ipc.oif))
			ipc.oif = inet->mc_index;
		if (!saddr)
			saddr = inet->mc_addr;
	} else if (!ipc.oif) {
		ipc.oif = inet->uc_index;
	} else if (ipv4_is_lbcast(daddr) && inet->uc_index) {
		if (ipc.oif != inet->uc_index &&
		    ipc.oif == l3mdev_master_ifindex_by_index(sock_net(sk),
							      inet->uc_index)) {
			ipc.oif = inet->uc_index;
		}
	}

	flow_flags = inet_sk_flowi_flags(sk);
	fl4 = &fl4_stack;
	flowi4_init_output(fl4, ipc.oif, ipc.sockc.mark, tos, scope,
			sk->sk_protocol, flow_flags, faddr, saddr,
			dport, inet->inet_sport, sk->sk_uid);

	rt = ip_route_output_flow(net, fl4, sk);
	if (IS_ERR(rt)) {
		pr_err("encrypted_socket: failed to ip_route_output_flow...");
		return PTR_ERR(rt);
	}

	err = encrypt_msghdr_data(msg, len);
	if (unlikely(err))
		return err;

	sk_dst_set(sk, dst_clone(&rt->dst));
	ip_rt_put(rt);

	return len;
}

static inline __sum16 encrypted_checksum(struct sk_buff *skb)
{
	return __skb_checksum_complete(skb);
}

static int encrypted_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
			     int flags, int *addr_len)
{
	struct encrypted_hdr *hdr;
	struct sk_buff *skb;
	unsigned int off, copied, ulen = 0;
	int err;

	skb = skb_recv_datagram(sk, flags, &err);
	if (!skb)
		return 0;

	hdr = encrypted_hdr(skb);

	if (encrypted_checksum(skb) != hdr->checksum) {
		pr_err("encrypted_socket: invalid checksum\n");
		msg->msg_flags &= ~MSG_TRUNC;
		return -EINVAL;
	}

	ulen = skb->len;
	copied = len;
	if (copied > ulen - off)
		copied = ulen - off;

	off = sk_peek_offset(sk, flags);
	err = skb_copy_datagram_msg(skb, off, msg, copied);
	if (unlikely(err))
		return err;

	err = decrypt_msghdr_data(msg, copied);
	if (unlikely(err))
		return err;

	return copied;
}

struct proto encrypted_prot = {
	.name		   = "ENCRYPTED",
	.owner		   = THIS_MODULE,
	.close		   = encrypted_close,
	.connect	   = ip4_datagram_connect, 
	.disconnect	   = encrypted_disconnect,
	.init		   = encrypted_sk_init,
	.destroy	   = encrypted_sk_destroy,
	.sendmsg	   = encrypted_sendmsg,
	.recvmsg	   = encrypted_recvmsg,
	.obj_size	   = sizeof(struct encrypted_sock),
};

static const struct proto_ops encrypted_ops = {
	.family		   = PF_INET,
	.owner		   = THIS_MODULE,
	.release	   = inet_release,
	.bind		   = inet_bind,
	.connect	   = inet_dgram_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = sock_no_accept,
	.poll		   = datagram_poll,
	.ioctl		   = inet_ioctl,
	.gettstamp	   = sock_gettstamp,
	.listen		   = sock_no_listen,
	.shutdown	   = inet_shutdown,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = inet_sendmsg,
	.recvmsg	   = sock_common_recvmsg,
	.mmap		   = sock_no_mmap,
};

static int encrypted_err(struct sk_buff *skb, u32 info)
{
	return 0;
}

static int encrypted_rcv(struct sk_buff *skb)
{
	struct encrypted_hdr *hdr = encrypted_hdr(skb);
	struct net *net = dev_net(skb->dev);
	unsigned short ulen;
	__be32 saddr, daddr;
	bool refcounted;
	struct sock *sk;

	ulen = ntohs(hdr->len);
	saddr = ip_hdr(skb)->saddr;
	daddr = ip_hdr(skb)->daddr;

	hdr->checksum = encrypted_checksum(skb);

	sk = inet_steal_sock(net, skb, sizeof(struct encrypted_hdr), saddr, hdr->src,
			daddr, hdr->dst, &refcounted, NULL);
	if (IS_ERR(sk)) {
		pr_err("Failed to steal socket\n");
		return -EINVAL;
	}

	if (sk)
		__skb_queue_tail(&sk->sk_receive_queue, skb);

	return 0;
}

static const struct net_protocol encrypted_protocol = {
	.handler	= encrypted_rcv,
	.err_handler	= encrypted_err,
	.no_policy	= 1,
};

static struct inet_protosw encrypted_protosw = {
	.type		=  SOCK_DGRAM,
	.protocol	=  IPPROTO_ENCRYPTED,
	.prot		=  &encrypted_prot,
	.ops		=  &encrypted_ops,
	.flags		=  INET_PROTOSW_PERMANENT,
};

void __init encrypted_register(void)
{
	if (proto_register(&encrypted_prot, 1)) {
		pr_err("Failed to register encrypted protocol");
		return;
	}

	if (inet_add_protocol(&encrypted_protocol, IPPROTO_ENCRYPTED) < 0)
		goto out;

	inet_register_protosw(&encrypted_protosw);

	pr_info("Encrypted protocol successfully registered!\n");

	return;

out:
	proto_unregister(&encrypted_prot);
}
