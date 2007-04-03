#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include "stopwatch.h"
#include "briefing.h"
#include "../headers/relay_test.h"

#define RELAYFILE "/debug/relay_test0"

#define NODFILE RELAY_CHRDEV_TEST_NAME "_nod"

void usage(void){
  printf("usage: relay_test [number of loops] [size of data chunk in bytes]\n");
  exit(1);
}

int main(int argc, char *argv[]){
  char *buf = NULL;
  unsigned long int time;
  int loops;
  int chunksize;
  int i;
  int ret;
  int fd;
  int sfd;
  dev_t numbers;
  
  if (argc < 3){
    usage();
  }

  if (sscanf(argv[1], "%d", &loops) != 1){
    usage();
  }
  
  if (sscanf(argv[2], "%d", &chunksize) != 1){
    usage();
  }
  
  // alloc memory for data chunk
  buf = (char *) malloc(chunksize * sizeof(char));
  if (buf == NULL){
    printf("malloc failed of chunksize %d\n", chunksize);
    return(2);
  }
  memset(buf, 0, chunksize); // not necessary
  
  fd = open(RELAYFILE, O_RDONLY);
  if (fd == -1){
    printf("file \"%s\" open failed\n", RELAYFILE);
    free(buf);
    return(3);
  }
  
  unlink(NODFILE);
  // prepare major and minor (minor is 0)
  numbers = 0xff00 & (RELAY_CHRDEV_TEST_MAJOR_N << 8);
  if (mknod(NODFILE, S_IFCHR, numbers) != 0){
    printf("cannot create nodfile \"%s\"\n", NODFILE);
    free(buf);
    return(4);
  }
  
  sfd = open(NODFILE, O_RDWR);
  if (sfd == -1){
    printf("file \"%s\" open failed\n", NODFILE);
    free(buf);
    return(4);
  }

  i = loops;
  ret = chunksize;
  
  stopwatchStart(); // start measuring
  while(i-- > 0 && ret == chunksize){
    ret = ioctl(sfd, 0, chunksize); // tell kernel to fill buffer of chunksize bytes
    if (ret == 0){
      ret = read(fd, buf, chunksize);
    }
  }
  time = stopwatchStop();
  if (ret == chunksize){
    printBriefing(0, loops, chunksize, time);
  }
  else{
    printf("test failed\n");
  }

  close(sfd);
  unlink(NODFILE);
  close(fd);
  free(buf);
  return(0);
}
