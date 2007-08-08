CC = gcc
CFLAGS = -Wall -pedantic

LIB_OBJS = \
	   av.o

TEST_OBJS = \
	    test/av_test.o

	
all: libav.a test/av_test

av.o: av.c av.h
	$(CC) $(CFLAGS) -c -o $@ $<

test/av_test.o: test/av_test.c av.h
	$(CC) $(CFLAGS) -c -o $@ $<

libav.a: $(LIB_OBJS)
	$(AR) $(ARFLAGS) $@ $^

test/av_test: $(TEST_OBJS) libav.a
	$(CC) $(CFLAGS) -o $@ $^ -lpthread

.PHONY: clean

clean:
	rm -rf test/av_test libav.a $(LIB_OBJS) $(TEST_OBJS)
