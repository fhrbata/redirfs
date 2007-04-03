#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "stopwatch.h"
#include "briefing.h"
#include "../headers/sysfs_test.h"

#define READ_TEST 0
#define WRITE_TEST 1
#define LATENCY_TEST 2

#define SYSFSDIR "/sys/sysfs_test/"
#define DATASIZEFILE SYSFSDIR "datasize"
#define PAGESIZEFILE SYSFSDIR "pagesize"
#define DATAPAGESDIR SYSFSDIR "datapages/"

int set_datasize(unsigned int size){
  FILE *f;
  unsigned int tmpsize;
  int retval;
  
  f = fopen(DATASIZEFILE, "w");
  if (f == NULL){
    printf("failed to open file \"%s\" for writing\n", DATASIZEFILE);
    return(-1);
  }
  fprintf(f, "%u\n", size);
  fclose(f);
  
  f = fopen(DATASIZEFILE, "r");
  if (f == NULL){
    printf("failed to open file \"%s\" for reading\n", DATASIZEFILE);
    return(-2);
  }
  retval = fscanf(f, "%u",  &tmpsize);
  fclose(f);
  
  if (retval != 1 || tmpsize != size){
    printf("cannot set datasize\n");
    return(-3);
  }
  return(0);
}

int get_pagesize(unsigned int *size){
  FILE *f;
  int retval;
  
  f = fopen(PAGESIZEFILE, "r");
  if (f == NULL){
    printf("failed to open file \"%s\" for reading\n", PAGESIZEFILE);
    return(-1);
  }
  retval = fscanf(f, "%u",  size);
  fclose(f);
  if (retval != 1){
    printf("cannot read page size\n");
    return(-2);
  }
  return(0);
}


void usage(void){
  printf("usage: sysfs_test [read/write/latency] [number of loops] [size of data chunk in bytes]\n");
  exit(1);
}

int main(int argc, char *argv[]){
  char *buf = NULL;
  unsigned long int time;
  int loops;
  int chunksize;
  int type;
  int i;
  int j;
  int ret;
  unsigned int pagesize;
  unsigned int numpages;
  int *fds;
  char filename[32];
  int len;

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
  
  if (set_datasize(chunksize) != 0){
    return(2);
  }
  
  if (get_pagesize(&pagesize) != 0){
    return(3);
  }
  
  numpages = GETNUMOFPAGES(chunksize, pagesize);
  
  // allocate filedescriptors array - one for each page
  fds = (int *) malloc(sizeof(int) * numpages);
  
  // alloc memory for data chunk
  buf = (char *) malloc(chunksize * sizeof(char));
  if (buf == NULL){
    printf("malloc failed of chunksize %d\n", chunksize);
    return(3);
  }
  memset(buf, 0, chunksize); // not necessary

  // open all used filedescriptors
  for(i = 0; i < numpages; i++){
    sprintf(filename, DATAPAGESDIR "%d", i);
//    printf("opening %s\n", filename);
    fds[i] = open(filename, O_RDWR);
    if (fds[i] == -1){
      printf("file \"%s\" open failed\n", filename);
      free(buf);
      // cleanup
      for(i--;i >=0; i--){
        close(fds[i]);
      }
      free(fds);
      return(4);
    }
  }

  i = loops;
  ret = 1;
  
  stopwatchStart(); // start measuring
  switch (type){
    case READ_TEST:
      while(i-- > 0 && ret){
        len = pagesize;
        for(j = 0; j < numpages && ret; j++){
          if (j == numpages - 1){ // last page may not be complete
	    len = chunksize - j * pagesize;
	  }
	  lseek(fds[j], 0, SEEK_SET);
          ret = (read(fds[j], buf, len) == len);
        }
      }
      break;
    case WRITE_TEST:
      while(i-- > 0 && ret){
        len = pagesize;
        for(j = 0; j < numpages && ret; j++){
          if (j == numpages - 1){ // last page may not be complete
	    len = chunksize - j * pagesize;
	  }
	  lseek(fds[j], 0, SEEK_SET);
          ret = (write(fds[j], buf, len) == len);
        }
      }
      break;
    case LATENCY_TEST:
      while(i-- > 0 && ret){
        lseek(fds[0], 0, SEEK_SET);
        ret = (write(fds[0], buf, chunksize) == chunksize);
	if (ret){
          lseek(fds[0], 0, SEEK_SET);
	  ret = (read(fds[0], buf, chunksize) == chunksize);
	}
      }
      break;
      default:
        ret = 0;
  }
  time = stopwatchStop();
  if (ret){
    printBriefing(type == LATENCY_TEST, loops, chunksize, time);
  }
  else{
    printf("test failed\n");
  }
 
  for(i = 0; i < numpages; i++){
    close(fds[i]);
  }
  free(fds);
  free(buf);
  return(0);
}
