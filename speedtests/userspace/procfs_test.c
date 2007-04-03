#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "stopwatch.h"
#include "briefing.h"

#define READ_TEST 0
#define WRITE_TEST 1
#define LATENCY_TEST 2

#define PROCFILE "/proc/test"

void usage(void){
  printf("usage: procfs_test [read/write/latency] [number of loops] [size of data chunk in bytes]\n");
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
  }
  else{
    chunksize = 1; // test latency with data chunk equal to one byte
  }
  
  // alloc memory for data chunk
  buf = (char *) malloc(chunksize * sizeof(char));
  if (buf == NULL){
    printf("malloc failed of chunksize %d\n", chunksize);
    return(2);
  }
  memset(buf, 0, chunksize); // not necessary
  
  fd = open(PROCFILE, O_RDWR);
  if (fd == -1){
    printf("file \"%s\" open failed\n", PROCFILE);
    free(buf);
    return(3);
  }

  // in read test we need to write data to kernel buffer first
  if (type == READ_TEST){
    if (write(fd, buf, chunksize) != chunksize){
      printf("read test prepare failed\n");
      free(buf);
      close(fd);
      return(4);
    }
  }
    
  i = loops;
  ret = chunksize;

  stopwatchStart(); // start measuring
  switch (type){
    case READ_TEST:
      while(i-- > 0 && ret == chunksize){
        lseek(fd, 0, SEEK_SET);
        ret = read(fd, buf, chunksize);
      }
      break;
    case WRITE_TEST:
      while(i-- > 0 && ret == chunksize){
        lseek(fd, 0, SEEK_SET);
        ret = write(fd, buf, chunksize);
      }
      break;
    case LATENCY_TEST:
      while(i-- > 0 && ret == chunksize){
        lseek(fd, 0, SEEK_SET);
        ret = write(fd, buf, chunksize);
	if (ret == chunksize){
	  ret = read(fd, buf, chunksize);
	}
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
  free(buf);
  return(0);
}
