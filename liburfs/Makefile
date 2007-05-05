CC = gcc

CFLAGS += -Wall -fPIC

INSTPREFIX = /usr/local
NAME = urfs
MAJORVERSION = 1
SUBVERSION = 0.0

all: lib$(NAME)

urfs.o: urfs.c
	$(CC) $^ -o $@ -c $(CFLAGS)

lib$(NAME): urfs.o
	$(CC) $^ -Wl,-soname,lib$(NAME).so.$(MAJORVERSION) -o lib$(NAME).so.$(MAJORVERSION).$(SUBVERSION) $(CFLAGS) -shared -lc

test: urfs.o test.c
	$(CC) $^ -o test

clean:
	rm -f *.o lib$(NAME)* test

install:
	mkdir -p $(INSTPREFIX)/lib/
	ln -s -f lib$(NAME).so.$(MAJORVERSION).$(SUBVERSION) lib$(NAME).so.$(MAJORVERSION)
	ln -s -f lib$(NAME).so.$(MAJORVERSION).$(SUBVERSION) lib$(NAME).so
	cp lib$(NAME).so* $(INSTPREFIX)/lib/ -P
	mkdir -p $(INSTPREFIX)/include/
	cp urfs.h $(INSTPREFIX)/include/
	chmod og+r $(INSTPREFIX)/lib/lib$(NAME).*

