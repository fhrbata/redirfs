CC = gcc

CFLAGS += -Wall

NAME = udummyflt

all: $(NAME)

$(NAME): $(NAME).c
	$(CC) $^ -o $@ $(CFLAGS) -lurfs

clean:
	rm -f *.o $(NAME)

