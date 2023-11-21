#ifndef __ENCRYPTED_H__
#define __ENCRYPTED_H__

struct encrypted_sock {
	/* inet_sock has to be the first member */
	struct inet_sock inet;
};

struct encrypted_hdr {
	__be16	src;
	__be16	dst;
	__be16	len;
	__sum16	checksum;
};

#define encrypted_sk(ptr) container_of_const(ptr, struct encrypted_sock, inet.sk)

void __init encrypted_register(void);

static inline struct encrypted_hdr *encrypted_hdr(const struct sk_buff *skb)
{
	return (struct encrypted_hdr *)skb_transport_header(skb);
}

#endif
