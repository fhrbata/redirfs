CC = gcc
CFLAGS += -Wall -pedantic

BIN_NAME := avtest
BIN_OBJS := avtest.o

.PHONY: all clean

all: $(BIN_NAME)

$(BIN_NAME): $(BIN_OBJS)
	$(CC) -o $(BIN_NAME) $(BIN_OBJS) -lav -lpthread

clean:
	$(RM) $(BIN_NAME) $(BIN_OBJS)

