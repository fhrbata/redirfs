#ifndef _NETLINK_TEST_H
#define _NETLINK_TEST_H

// commands
#define READ_TEST 0
#define WRITE_TEST 1
#define LATENCY_TEST 2
#define SET_BUFSIZE 3

#define NETLINK_TEST 17 // protocol type

#define MAX_PAYLOAD 16384

#define ANSWER_ACK 0x01
#define ANSWER_ERR 0x02

#define ANSWER_BORDER 110000 // if sent data reached this number we need the answer from other side (to precede slab overflow)

// ANSWER_BORDER + MAX_PAYLOAD <= SLAB SIZE - SKBUFF HEADER SIZE - NLMSG HEADER 

#endif
