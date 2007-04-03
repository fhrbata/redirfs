#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <errno.h>
#include "stopwatch.h"
#include "briefing.h"
#include "../headers/netlink_test.h"

struct sockaddr_nl *daddr;
struct msghdr *msg; 
struct iovec *iov;
struct nlmsghdr *nlh;
struct sockaddr_nl *idaddr;	
struct msghdr *imsg; 
struct iovec *iiov;
struct nlmsghdr *inlh;

int prepareOutputHeaders(int payload){
  // prepare data structures for output messages
  nlh = (struct nlmsghdr *) malloc(NLMSG_SPACE(payload)); // we will carry only one byte
  if (!nlh){
    return(-1);
  }
  daddr = (struct sockaddr_nl *) malloc(sizeof(struct sockaddr_nl));
  if (!daddr){
    free(nlh);
    return(-2);
  }
  msg = (struct msghdr *) malloc(sizeof(struct msghdr));
  if (!msg){
    free(nlh);
    free(daddr);
    return(-3);
  }
  iov = (struct iovec *) malloc(sizeof(struct iovec));
  if (!iov){
    free(nlh);
    free(daddr);
    free(msg);
    return(-4);
  }

  // set destination address
  memset(daddr, 0, sizeof(struct sockaddr_nl));
  daddr->nl_family = AF_NETLINK;
  daddr->nl_pid = 0; // destination is kernel
  // fill the netlink message header
  nlh->nlmsg_len = NLMSG_SPACE(payload);
  nlh->nlmsg_pid = getpid();
  nlh->nlmsg_flags = 0;
  nlh->nlmsg_type = 0;
  nlh->nlmsg_seq = 0;
  // assemble the header
  msg->msg_name = (void *) daddr;
  msg->msg_namelen = sizeof(struct sockaddr_nl);
  iov->iov_base = (void *) nlh;
  iov->iov_len = nlh->nlmsg_len;
  msg->msg_iov = iov;
  msg->msg_iovlen = 1;
  return(payload);
}

int prepareInputHeaders(int payload){
  // prepare data structures for input messages
  inlh = (struct nlmsghdr *) malloc(NLMSG_SPACE(payload)); // we will carry only one byte
  if (!inlh){
    return(-1);
  }
  idaddr = (struct sockaddr_nl *) malloc(sizeof(struct sockaddr_nl));
  if (!idaddr){
    free(inlh);
    return(-2);
  }
  imsg = (struct msghdr *) malloc(sizeof(struct msghdr));
  if (!imsg){
    free(inlh);
    free(idaddr);
    return(-3);
  }
  iiov = (struct iovec *) malloc(sizeof(struct iovec));
  if (!iiov){
    free(inlh);
    free(idaddr);
    free(imsg);
    return(-4);
  }

  // fill the netlink message header
  inlh->nlmsg_len = NLMSG_SPACE(payload);
  // assemble the header
  imsg->msg_name = (void *) idaddr;
  imsg->msg_namelen = sizeof(struct sockaddr_nl);
  iiov->iov_base = (void *) inlh;
  iiov->iov_len = inlh->nlmsg_len;
  imsg->msg_iov = iiov;
  imsg->msg_iovlen = 1;
  return(payload);
}

void freeHeaders(void){
  free(nlh);
  free(daddr);
  free(msg);
  free(iov);
  free(inlh);
  free(idaddr);
  free(imsg);
  free(iiov);
}

int read_test(int sock_fd, int loops, int chunksize, char *buf){
  int i = loops;
  char *data = NLMSG_DATA(nlh);
  char *idata = NLMSG_DATA(inlh);
  int offset;
  int len;

  nlh->nlmsg_len = NLMSG_SPACE(1); // gonna send only command byte
  data[0] = READ_TEST; // set command to message (first byte)
  while(i-- > 0){
    offset = 0;
    inlh->nlmsg_type |= NLMSG_DONE; // prepare this to look like DONE came - for first pass
    // recieve multiple messages containing desired data
    while(offset != chunksize){
      if (inlh->nlmsg_type & NLMSG_DONE){
        // send command to kernel (on start or when received DONE from kernel)
        if (sendmsg(sock_fd, msg, 0) == -1){
          return(-1);
        }
      }

      // read message from kernel
      memset(inlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
      if (recvmsg(sock_fd, imsg, 0) == -1){
        return(-2);
      }      
      len = inlh->nlmsg_len - NLMSG_HDRLEN; // get payload size (with align which we do not care)
      if (chunksize - offset < len){ // if message is bigger than space left in our buffer
        len = chunksize - offset; // cut it
      }
      if (len == 0){ // kernel have nothing to send and we still need to recieve
        return(-3);
      }
      memcpy(buf + offset, idata, len);
      offset += len;
    }
  }
  return(0);
}

int write_test(int sock_fd, int loops, int chunksize, char *buf){
  int i = loops;
  char *data = NLMSG_DATA(nlh);
  int offset;
  int answers;
  int len;

  data[0] = WRITE_TEST; // set command to message (first byte)
  while(i-- > 0){
    offset = 0;
    answers = 0;
    // send data to kernel in multiple messages
    while(offset != chunksize){
      if (chunksize - offset > MAX_PAYLOAD - 1){ // 1 stands for command byte
        len = MAX_PAYLOAD - 1;
      }
      else{
        len = chunksize - offset;
      }
      memcpy(data + 1, buf + offset, len);
      nlh->nlmsg_len = NLMSG_SPACE(len + 1);
      offset += len;
      // need to set done flag to indicate kernel to send answer after reaching ANSWER_BORDER (by next message which we assume at least the smae length as this)
      if (offset + len / ANSWER_BORDER > answers ||
	  offset == chunksize){
	nlh->nlmsg_type = NLMSG_DONE;
	answers++;
      }
      else{
	nlh->nlmsg_type = 0;
      }
      if (sendmsg(sock_fd, msg, 0) == -1){
        return(-1);
      }
      
      if (nlh->nlmsg_type & NLMSG_DONE){
        // read message from kernel (only one byte)
        memset(inlh, 0, NLMSG_SPACE(1));
        if (recvmsg(sock_fd, imsg, 0) == -1){
          return(-2);
        }
        if (*((char *)(NLMSG_DATA(inlh))) != ANSWER_ACK){ // check answer
          return(-3);
        }
	answers++;
      }
    }
  }
  return(0);
}

int latency_test(int sock_fd, int loops){
  int i = loops;

  nlh->nlmsg_len = NLMSG_SPACE(1); // gonna send only command byte
  *((char *)(NLMSG_DATA(nlh))) = LATENCY_TEST; // set command to message (first byte)
  while(i-- > 0){
    if (sendmsg(sock_fd, msg, 0) == -1){
      return(-1);
    }
    // read message from kernel (only one byte)
    memset(inlh, 0, NLMSG_SPACE(1));
    if (recvmsg(sock_fd, imsg, 0) == -1){
      return(-2);
    }
    if (*((char *)(NLMSG_DATA(inlh))) != ANSWER_ACK){ // check returned payload
      return(-3);
    }
  }
  return(0);
}

int set_bufsize(int sock_fd, int chunksize){
  int i = 0;
  char *data = NLMSG_DATA(nlh);

  data[i++] = SET_BUFSIZE; // set command to message (first byte)
  data[i++] = (((unsigned int) chunksize) >> 24) & 0xff;    
  data[i++] = (((unsigned int) chunksize) >> 16) & 0xff;
  data[i++] = (((unsigned int) chunksize) >> 8) & 0xff;
  data[i++] = ((unsigned int) chunksize) & 0xff;
  nlh->nlmsg_len = NLMSG_SPACE(5);

  if (sendmsg(sock_fd, msg, 0) == -1){
    return(-1);
  }
  
  // read message from kernel
  memset(inlh, 0, NLMSG_SPACE(1));
  if (recvmsg(sock_fd, imsg, 0) == -1){
    return(-2);
  }
  if (*((char *)(NLMSG_DATA(inlh))) != ANSWER_ACK){ // check returned payload
    return(-3);
  }
  return(0);
}

void usage(void){
  printf("usage: netlink_test [read/write/latency] [number of loops] [size of data chunk in bytes]\n");
  exit(1);
}

int main(int argc, char *argv[]){
  char *buf = NULL;
  unsigned long int time;
  int loops;
  int chunksize;
  int type;
  int i;
  int ret;
  int sock_fd;
  struct sockaddr_nl myaddr;

  if (argc < 3){
    usage();
  }

  if (strcmp(argv[1], "read") == 0){
    type = READ_TEST;
  }
  else  if (strcmp(argv[1], "write") == 0){
    type = WRITE_TEST;
  }
  else  if (strcmp(argv[1], "latency") == 0){
    type = LATENCY_TEST;
  }
  else{
    usage();
  }

  if (sscanf(argv[2], "%d", &loops) != 1){
    usage();
  }

  if (prepareOutputHeaders(MAX_PAYLOAD) < 0){
    printf("error preparing input headers\n");
    return(2);
  }
  if (prepareInputHeaders(MAX_PAYLOAD) < 0){
    printf("error preparing output headers\n");
    return(3);
  }
  
  if (type != LATENCY_TEST){
    if (argc != 4 || sscanf(argv[3], "%d", &chunksize) != 1){
      usage();
    }
    // alloc memory for data chunk
    buf = (char *) malloc(chunksize * sizeof(char));
    if (buf == NULL){
      printf("malloc failed of chunksize %d\n", chunksize);
      return(4);
    }
    memset(buf, 0, chunksize); // not necessary
  }

  // open socket
  sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_TEST);
  if (sock_fd == -1){
    printf("socket open failed\n");
    return(5);
  }
  
  // set our address
  memset(&myaddr, 0, sizeof(struct sockaddr_nl));
  myaddr.nl_family = AF_NETLINK;
  myaddr.nl_pid = getpid();
  
  // now bind address
  if (bind(sock_fd, (struct sockaddr *) &myaddr, sizeof(struct sockaddr_nl)) != 0){
    printf("bind failed\n");
    return(6);
  }

  if (type != LATENCY_TEST){
    if (set_bufsize(sock_fd, chunksize) != 0){
      printf("failed to set kernel buffer size (reached maximum kernel buffer size?)\n");
      return(7);      
    }
  }

  i = loops;
  ret = 1;

  stopwatchStart(); // start measuring
  switch (type){
    case READ_TEST:
      ret = read_test(sock_fd, loops, chunksize, buf);
      break;
    case WRITE_TEST:
      ret = write_test(sock_fd, loops, chunksize, buf);
      break;
    case LATENCY_TEST:
      ret = latency_test(sock_fd, loops);
      break;
      default:
        ret = -1;
  }
  time = stopwatchStop();
  if (ret == 0){
    printBriefing(type == LATENCY_TEST, loops, chunksize, time);
  }
  else{
    printf("test failed\n");
  }
 
  free(buf);

  freeHeaders();

  close(sock_fd);

  return(0);
}
