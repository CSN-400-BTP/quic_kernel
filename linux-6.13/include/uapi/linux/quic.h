#ifndef _UAPI_LINUX_QUIC_H
#define _UAPI_LINUX_QUIC_H

#include <linux/types.h>

/* * The unique ID for our custom socket type. 
 * Using 11 ensures we are outside the standard TCP/UDP range.
 */
#define SOCK_QUIC 11

/* * A minimal QUIC Header
 * We use __attribute__((packed)) to ensure the compiler doesn't 
 * add "padding" bytes, keeping the header exactly 5 bytes.
 */
struct quichdr {
    __u8    flags;          /* 1 byte: Packet type / flags */
    __u32   connection_id;  /* 4 bytes: Unique ID for the session */
} __attribute__((packed));

#endif /* _UAPI_LINUX_QUIC_H */