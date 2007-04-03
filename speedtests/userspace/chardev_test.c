#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "stopwatch.h"
#include "briefing.h"
#include "../headers/chardev_test.h"

#define READ_TEST 0
#define WRITE_TEST 1
#define LATENCY_TEST 2

#define NODFILE CHARDEV_TEST_NAME "_nod"

void usage(void){
  printf("usage: chardev_test [read/write/latency] [number of loops] [size of data chunk in bytes]\n");
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
  int fd;
  dev_t numbers;

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
  
  if (type != LATENCY_TEST){
    if (argc != 4 || sscanf(argv[3], "%d", &chunksize) != 1){
      usage();
    }
  
    // alloc memory for data chunk
    buf = (char *) malloc(chunksize * sizeof(char));
    if (buf == NULL){
      printf("malloc failed of chunksize %d\n", chunksize);
      return(2);
    }
    memset(buf, 0, chunksize); // not necessary
  }
  else{
    chunksize = 0;
  }
  
  unlink(NODFILE);
  // prepare major and minor (minor is 0)
  numbers = 0xff00 & (CHARDEV_TEST_MAJOR_N << 8);
  if (mknod(NODFILE, S_IFCHR, numbers) != 0){
    printf("cannot create nodfile \"%s\"\n", NODFILE);
    return(3);
  }

  
  fd = open(NODFILE, O_RDWR);
  if (fd == -1){
    printf("file \"%s\" open failed\n", NODFILE);
    free(buf);
    return(4);
  }

  i = loops;
  ret = chunksize;

  stopwatchStart(); // start measuring
  switch (type){
    case READ_TEST:
      while(i-- > 0 && ret == chunksize){
        ret = read(fd, buf, chunksize);
      }
      break;
    case WRITE_TEST:
      while(i-- > 0 && ret == chunksize){
        ret = write(fd, buf, chunksize);
      }
      break;
    case LATENCY_TEST:
      while(i-- > 0 && ret == chunksize){
        ret = ioctl(fd, 0, 0); // 0 is success as so as chunksize for latency test so we can control it in the similar way
      }
      break;
      default:
        ret = -1;
  }
  time = stopwatchStop();
  if (ret == chunksize){
    printBriefing(type == LATENCY_TEST, loops, chunksize, time);
  }
  else{
    printf("test failed\n");
  }

  close(fd);
  unlink(NODFILE);
  free(buf);
  return(0);
}
