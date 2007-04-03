#include <linux/module.h>
#include <linux/version.h>
#include <linux/init.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include "buffer.h"
#include "../headers/netlink_test.h"

#define PRINTPREFIX "netlink_test: "

static unsigned int locbuf_currbase;
int read_answers;

static DEFINE_MUTEX(rx_queue_mutex);

static void test_rcv(struct sock *sk, int len){
  struct sk_buff *skb;
  struct nlmsghdr *nlh;
  char *data;
  pid_t pid;
  unsigned int nlen, i;
  char answer = ANSWER_ACK;

  mutex_lock(&rx_queue_mutex);
  while((skb = skb_dequeue(&sk->sk_receive_queue)) != NULL){ // take one message per another
    nlh = (struct nlmsghdr *)skb->data; // get message from buffer
    nlen = nlh->nlmsg_len - NLMSG_HDRLEN;
    data = NLMSG_DATA(nlh); // get data payload
    pid = nlh->nlmsg_pid; // pid of sending process
    i = 0;
    switch (data[i++]){ // command
      case READ_TEST:
        {
          struct sk_buff *oskb;
          struct nlmsghdr *onlh;
	  int olen;
	  int next = 1;
	  
          //printk(PRINTPREFIX "read test\n");
	  // now free socket buffer (it must be done if we do not use the same buffer to send message back)
          skb_pull(skb, skb->len);
	  kfree_skb(skb);

          while(locbuf_currbase < locbuf_currlen && next){
            // create buffer for answer
            oskb = alloc_skb(NLMSG_SPACE(MAX_PAYLOAD), GFP_ATOMIC);
            if (!oskb){
  	      printk(PRINTPREFIX "fatal! skbuff alloc failed\n");
	      locbuf_currbase = 0; // zero base for next operation
	      return;
	    }

	    onlh = (struct nlmsghdr *) skb_put(oskb, NLMSG_SPACE(MAX_PAYLOAD));
	    data = NLMSG_DATA(onlh);
	    // set payload
	    if (locbuf_currlen - locbuf_currbase > MAX_PAYLOAD){
              olen = MAX_PAYLOAD;
            }
	    else{
              olen = locbuf_currlen - locbuf_currbase;
	    }
	    //printk(PRINTPREFIX "sending %d bytes from offset %u\n", olen, locbuf_currbase);
            memcpy(data, locbuf + locbuf_currbase, olen);            
	    locbuf_currbase += olen;
	    
	    onlh->nlmsg_len = NLMSG_SPACE(olen);
	    onlh->nlmsg_pid = 0; // from kernel
            NETLINK_CB(oskb).pid = 0; // from kernel
            NETLINK_CB(oskb).dst_pid = pid;
            NETLINK_CB(oskb).dst_group = 0; // unicast
	    if (locbuf_currbase + olen / ANSWER_BORDER > read_answers){ // assume next message should be at least the same length as this
	      //printk(PRINTPREFIX "border reached\n");
  	      onlh->nlmsg_type = NLMSG_DONE;
	      read_answers++;
	      next = 0; // not enter next loop
	    }
	    else{
	      onlh->nlmsg_type = 0;
	    }
	    //printk(PRINTPREFIX "sending to pid: %d\n", pid);
            netlink_unicast(sk, oskb, pid, 0);
	  }
	  if (locbuf_currbase == locbuf_currlen){ // if it's end
	    locbuf_currbase = 0; // zero base for next operation
	    read_answers = 0;
	  }
	}
        break;
      case WRITE_TEST:
        {
          //printk(PRINTPREFIX "write test\n");
  	  nlen -= i;
	  // compute datachunk length if we are at the end of buffer
	  if (locbuf_currlen - locbuf_currbase <= nlen){
	    nlen = locbuf_currlen - locbuf_currbase;
	  }
	  //printk(PRINTPREFIX "writing %d bytes to offset %u\n", nlen, locbuf_currbase);
	  memcpy(locbuf + locbuf_currbase, data + i, nlen);
          locbuf_currbase += nlen;
	  if (!(nlh->nlmsg_type & NLMSG_DONE)){ // not answer?
	    // now free socket buffer when we won't use it to send message back 
            skb_pull(skb, skb->len);
	    kfree_skb(skb);
	  }
	  else{
	    if (locbuf_currbase == locbuf_currlen){
	      locbuf_currbase = 0; // zero base for next operation
	      //printk(PRINTPREFIX "zeroing currbase\n");
	    }
            // use message buffer to reply (only one byte so it will always fit into allocated skb)
	    nlh->nlmsg_len = NLMSG_SPACE(1);
	    NETLINK_CB(skb).pid = 0; // from kernel
            NETLINK_CB(skb).dst_pid = pid;
            NETLINK_CB(skb).dst_group = 0; // unicast
	    data[0] = answer; // set answer
	    //printk(PRINTPREFIX "sending to pid: %d\n", pid);
            netlink_unicast(sk, skb, pid, 0);
	  }
	}
        break;
      case LATENCY_TEST:
        //printk(PRINTPREFIX "latency test\n");
        // just take received message, change addresses and send back
        nlh->nlmsg_len = NLMSG_SPACE(1);
        NETLINK_CB(skb).pid = 0; // from kernel
        NETLINK_CB(skb).dst_pid = pid;
        NETLINK_CB(skb).dst_group = 0; // unicast
	data[0] = answer; // set answer
	//printk(PRINTPREFIX "sending to pid: %d\n", pid);
        netlink_unicast(sk, skb, pid, 0);
	break;
      case SET_BUFSIZE:
        //printk(PRINTPREFIX "set buffer size\n");
        if (nlen < 5){ // 1 byte command + 4 bytes new buffer size
	  answer = ANSWER_ERR;
	}
	else{
	  unsigned int tmpsize;
	  
	  tmpsize = ((data[i] & 0xff) << 24) | ((data[i + 1] & 0xff) << 16) | ((data[i + 2] & 0xff) << 8) | (data[i + 3] & 0xff); // set it by next 4 bytes
	  if (tmpsize > LOCBUFLEN){
	    //printk(PRINTPREFIX "size is bigger than buffer\n");
	    answer = ANSWER_ERR;
	  }
	  else{
	    //printk(PRINTPREFIX "setting buffer length to %d bytes\n", tmpsize);
	    locbuf_currlen = tmpsize;
	  }
        }
        nlh->nlmsg_len = NLMSG_SPACE(1);
        NETLINK_CB(skb).pid = 0; // from kernel
        NETLINK_CB(skb).dst_pid = pid;
        NETLINK_CB(skb).dst_group = 0; // unicast
	data[0] = answer; // set answer
	//printk(PRINTPREFIX "sending to pid: %d\n", pid);
        netlink_unicast(sk, skb, pid, 0);
	locbuf_currbase = 0;
        read_answers = 0;
        break;
    }
  }
  mutex_unlock(&rx_queue_mutex);
}

static struct sock *test_sk;

static int __init _init_module(void){
  if (!alloc_locbuf()){
    printk(PRINTPREFIX "Cannot allocate local buffer\n");
    return(-1);
  }
  test_sk = netlink_kernel_create(NETLINK_TEST, 0, test_rcv, THIS_MODULE);
  if (!test_sk){
    printk(PRINTPREFIX "Cannot initialize netlink socket\n");
    free_locbuf();
    return(-1);
  }
  // set lenght of used data in local buffer
  locbuf_currlen = 0;
  locbuf_currbase = 0;
  read_answers = 0;
  printk(PRINTPREFIX "Netlink test initialized\n");
  
  return(0);
}

static void __exit _cleanup_module(void){
  free_locbuf();
  sock_release(test_sk->sk_socket);
}

module_init(_init_module);
module_exit(_cleanup_module);

MODULE_LICENSE("GPL");
