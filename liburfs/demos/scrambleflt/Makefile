CC = gcc

CFLAGS += -Wall

NAME = scrambleflt

all: $(NAME)

$(NAME): $(NAME).c
	$(CC) $^ -o $@ $(CFLAGS) -lurfs

clean:
	rm -f *.o $(NAME)

