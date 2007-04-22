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

redirctl: urfs.o redirctl.c
	$(CC) $^ -o redirctl

clean:
	rm -f *.o lib$(NAME)* redirctl

install:
	mkdir -p $(INSTPREFIX)/lib/
	ln -s -f lib$(NAME).so.$(MAJORVERSION).$(SUBVERSION) lib$(NAME).so.$(MAJORVERSION)
	ln -s -f lib$(NAME).so.$(MAJORVERSION).$(SUBVERSION) lib$(NAME).so
	cp lib$(NAME).so* $(INSTPREFIX)/lib/ -P
	mkdir -p $(INSTPREFIX)/include/
	cp rfs.h $(INSTPREFIX)/include/
	chmod og+r $(INSTPREFIX)/lib/lib$(NAME).*
	chmod -R og+r $(INSTPREFIX)/include/$(NAME)
