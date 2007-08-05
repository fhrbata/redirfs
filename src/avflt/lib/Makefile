CC = gcc
CFLAGS = -Wall -pedantic

OBJS = \
       av.o

all: libav.a

av.o: av.c av.h
	$(CC) $(CFLAGS) -c -o $@ $<

libav.a: $(OBJS)
	$(AR) $(ARFLAGS) $@ $^

.PHONY: clean

clean:
	rm -rf libav.a $(OBJS)
