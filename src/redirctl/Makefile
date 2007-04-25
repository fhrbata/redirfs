CC = gcc

CFLAGS += -Wall -fPIC

NAME = redirctl

all: $(NAME)

$(NAME): redirctl.c
	$(CC) $< -o $@

clean:
	rm -f $(NAME)
	rm -f *~
