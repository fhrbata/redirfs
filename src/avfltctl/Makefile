CC = gcc
CFLAGS += -Wall -pedantic

ifdef DEBUG
CFLAGS += -g -O0
endif

BIN_NAME := avfltctl
BIN_OBJS := avfltctl.o
BIN_DIR := /usr/bin

.PHONY: all install uninstall clean

all: $(BIN_NAME)

$(BIN_NAME): $(BIN_OBJS)
	$(CC) -o $(BIN_NAME) $(BIN_OBJS) -lavfltctl

install: $(BIN_NAME)
	cp $(BIN_NAME) $(BIN_DIR)/$(BIN_NAME)

uninstall:
	$(RM) $(BIN_DIR)/$(BIN_NAME)
clean:
	$(RM) $(BIN_NAME) $(BIN_OBJS)

