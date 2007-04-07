SRC = read.c write.c
OBJ = ${SRC:.c=.o}

all: ${OBJ}

.c.o:
	cc -c ${CFLAGS} $< -o $*

clean:
	rm -f *.o read write
