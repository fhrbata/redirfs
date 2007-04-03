#include <stdio.h>
#include "briefing.h"

void printBriefing(int wantdelay, int loops, int chunksize, unsigned long int time){
#ifdef __SHORT_BRIEFING
  //printf("chunksize: %dB, loops: %d, total time: %ldus, one loop time: %lfus\n", chunksize, loops, time, (double) time / (double) loops);
  if (wantdelay){
    printf("%lf\n", (double) time / (double) loops);
  }
  else{
    printf("%lf ", ((double) 1 / ((double) time / (double) loops)) * chunksize * 1000000);
  }
#else  
  printf("chunksize: %dB\n", chunksize);
  printf("loops: %d\n", loops);
  printf("total time: %ld usecs\n", time);
  printf("average %lf usecs per loop\n", (double) time / (double) loops);
  printf("bandwidth: %lf B/s\n", ((double) 1 / ((double) time / (double) loops)) * chunksize * 1000000);
#endif
}
