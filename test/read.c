#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "../compflt/path.h"

#define FILE COMPFLT_INC_DIR "/test"

int main(void)
{
	int fd;
	char buff[8192];

	fd = open(FILE, O_RDONLY);
	lseek(fd, 0, SEEK_SET);
	read(fd, buff, 100);
	read(fd, buff, 100);
	lseek(fd, 500, SEEK_SET);
	read(fd, buff, 300);
	// off = 800
	read(fd, buff, 8192);
	lseek(fd, -10, SEEK_CUR);
	read(fd, buff, 100);

	/* bugged atm
	lseek(fd, -10, SEEK_END);
	read(fd, buff, 100);
	*/

	close(fd);
	return 0;
}
