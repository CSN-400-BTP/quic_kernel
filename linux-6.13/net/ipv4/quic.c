#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/udp.h>
#include <linux/inet.h>
#include <net/udp.h>
#include <net/protocol.h>
#include <net/inet_common.h>

/* New handlers */
int quic_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
int quic_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len);

/* 1. Wrapper for get_port */
static int quic_v4_get_port(struct sock *sk, unsigned short snum)
{
    /* We just call the UDP version, passing 0 or a default for the 3rd arg */
    return udp_lib_get_port(sk, snum, 0);
}

/* 2. Wrapper for rehash */
static void quic_v4_rehash(struct sock *sk)
{
    /* Call UDP version with default port arguments (0, 0) */
    udp_lib_rehash(sk, 0, 0);
}

struct proto quic_prot = {
    .name		 = "QUIC",
    .owner		 = THIS_MODULE,
    .obj_size	 = sizeof(struct udp_sock),
    .init        = udp_init_sock,
    .sendmsg	 = quic_sendmsg,
    .recvmsg	 = quic_recvmsg,
    .close       = udp_lib_close,
    .backlog_rcv =sock_queue_rcv_skb,
    .connect     = ip4_datagram_connect,
    .release_cb  = ip4_datagram_release_cb,
    /* We reuse UDP's standard hash/unhash to keep things simple for now */
    .get_port    = quic_v4_get_port,
    .hash		 = udp_lib_hash,
    .unhash		 = udp_lib_unhash,
    .rehash      = quic_v4_rehash
};
EXPORT_SYMBOL(quic_prot); 

int quic_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{       
    int err;
    printk(KERN_INFO "QUIC_LOG: SEND is being called PID: %d", current->pid);
    if (len >= 5) {
        printk(KERN_INFO "QUIC_LOG : SEND Intercepted packet of length %zu\n", len);
    }


    /* Hand off to the standard UDP implementation */

    // sk->sk_prot = &udp_prot;
    err = udp_prot.sendmsg(sk, msg, len);
    printk(KERN_INFO "QUIC_LOG : SEND at end, err : %d", err);
    // sk->sk_prot = orig_quic_prot;

    return err;
}

int quic_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len)
{   
    printk(KERN_INFO "QUIC_LOG: RECV is being called");
    int err;

    /* Call standard UDP receive first to get the data into the kernel */
    err = udp_prot.recvmsg(sk, msg, len, flags, addr_len);

    if (err >= 5) {
        printk(KERN_INFO "QUIC_LOG : RECV Received %d bytes\n", err);
    }

    return err;
}