#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include "stopwatch.h"
#include "briefing.h"
#include "../headers/syscall_test.h"

#define TEST_SYSCALL_NR 280

void usage(void){
  printf("usage: syscall_test [read/write/latency] [number of loops] [size of data chunk in bytes]\n");
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
    if (syscall(TEST_SYSCALL_NR, ALLOC_BUFFER, 0, 0) != 0){ // allocate kernel buffer
      printf("cannot allocate kernel buffer\n");
      free(buf);
      return(3);
    }
  }
    
  i = loops;
  ret = 0;
  
  stopwatchStart(); // start measuring
  while(i-- > 0 && ret == 0){
    ret = syscall(TEST_SYSCALL_NR, type, buf, chunksize);  
  }
  time = stopwatchStop();
  if (ret != 0){
    printf("syscall failed with return value %d\n", ret);
  }
  else{
    printBriefing(type == LATENCY_TEST, loops, chunksize, time);
  }

  if (type != LATENCY_TEST){
    free(buf);
    syscall(TEST_SYSCALL_NR, FREE_BUFFER, 0, 0); // free kernel buffer
  }
  return(0);
}
