#ifndef _BUFFER_H
#define _BUFFER_H

//#define __DYNAMIC_BUFFER

#define LOCBUFLEN (4*8*128*1024)
#ifdef __DYNAMIC_BUFFER
static char *locbuf;
#else
static char locbuf[LOCBUFLEN];
#endif
#ifndef __NOCURRLEN
static unsigned int locbuf_currlen;
#endif

inline char *alloc_locbuf(void){
#ifdef __DYNAMIC_BUFFER
  locbuf = (char *) kmalloc(sizeof(char) * LOCBUFLEN, GFP_KERNEL);
#endif
  return(locbuf);
}

inline void free_locbuf(void){
#ifdef __DYNAMIC_BUFFER
  kfree(locbuf);
#endif
}

#endif
