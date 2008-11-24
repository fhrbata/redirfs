CC = gcc
CFLAGS += -Wall -pedantic

ifdef DEBUG
CFLAGS += -g -O0
endif

BIN_NAME := avtest
BIN_OBJS := avtest.o
BIN_DIR := /usr/bin

.PHONY: all install uninstall clean

all: $(BIN_NAME)

$(BIN_NAME): $(BIN_OBJS)
	$(CC) -o $(BIN_NAME) $(BIN_OBJS) -lav -lpthread

install: $(BIN_NAME)
	cp $(BIN_NAME) $(BIN_DIR)/$(BIN_NAME)

uninstall:
	$(RM) $(BIN_DIR)/$(BIN_NAME)

clean:
	$(RM) $(BIN_NAME) $(BIN_OBJS)

