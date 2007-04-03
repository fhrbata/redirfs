#include <sys/time.h>
#include <time.h>
#include "stopwatch.h"

static struct timeval startTime;

// starts stopwatch counting
void stopwatchStart(void){
  gettimeofday(&startTime, (struct timezone *) NULL);
}

// returns measured time in micro seconds
unsigned long int stopwatchStop(void){
  struct timeval stopTime;

  gettimeofday(&stopTime, (struct timezone *) NULL);
  return((stopTime.tv_sec - startTime.tv_sec) * 1000000 + (stopTime.tv_usec - startTime.tv_usec));
}
