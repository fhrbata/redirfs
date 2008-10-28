CC = gcc
CFLAGS += -g -O0 -Wall -pedantic

LIBRFSCTL_OBJS := rfsctl.o
REDIRFSCTL_OBJS := redirfsctl.o

all: redirfsctl librfsctl.a

redirfsctl: $(REDIRFSCTL_OBJS) librfsctl.a
	$(CC) -o redirfsctl $(REDIRFSCTL_OBJS) librfsctl.a

librfsctl.a: $(LIBRFSCTL_OBJS)
	$(AR) $(ARFLAGS) librfsctl.a $(LIBRFSCTL_OBJS)

PHONY: clean

clean:
	$(RM) redirfsctl librfsctl.a $(LIBRFSCTL_OBJS) $(REDIRFSCTL_OBJS)
