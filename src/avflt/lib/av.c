#include "av.h"
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int av_register(struct av_con *avc)
{
	int fd;

	if (!avc)
		return -EINVAL;

	fd = open("/dev/avflt", O_RDWR);
	if (fd == -1)
		return errno;

	avc->fd = fd;

	return 0;
}

int av_unregister(struct av_con *avc)
{
	if (!avc)
		return -EINVAL;

	if (close(avc->fd) == -1)
		return errno;

	return 0;
}

int av_request(struct av_con *avc, struct av_req *avr)
{
	if (!avc || !avr)
		return -EINVAL;

	memset((void*)avr, 0, sizeof(struct av_req));
	avr->ucheck.mag = AV_CTL_MAGIC;
	avr->ucheck.ver = AV_CTL_VERSION;
	avr->ucheck.fn = avr->fn;
	avr->ucheck.fn_size = PATH_MAX;

	if (read(avc->fd, &avr->ucheck, sizeof(struct avflt_ucheck)) == -1)
		return errno;

	return 0;
}

int av_reply(struct av_con *avc, struct av_req *avr)
{
	if (!avc || !avr)
		return -EINVAL;

	if (write(avc->fd, &avr->ucheck, sizeof(struct avflt_ucheck)) == -1)
		return errno;

	return 0;
}

int av_access(struct av_con *avc, struct av_req *avr, int ava)
{
	if (!avc || !avr)
		return -EINVAL;

	avr->ucheck.deny = !ava;

	return 0;
}
