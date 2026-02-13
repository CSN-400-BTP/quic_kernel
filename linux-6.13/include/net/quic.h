#ifndef _NET_QUIC_H
#define _NET_QUIC_H

#include <uapi/linux/quic.h> /* Pulls in SOCK_QUIC and struct quichdr */
#include <linux/net.h>
#include <net/protocol.h>

/* Internal kernel blueprint */
extern struct proto quic_prot;

/* Function prototypes for quic.c */
int quic_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
int quic_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len);

#endif