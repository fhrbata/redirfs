#include "av.h"
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

int av_register(struct av_con *avc)
{
	int fd;

	if (!avc)
		return EINVAL;

	fd = open("/dev/avflt", O_RDWR);
	if (fd == -1)
		return errno;

	avc->fd = fd;

	return 0;
}

int av_unregister(struct av_con *avc)
{
	if (!avc)
		return EINVAL;

	if (close(avc->fd) == -1)
		return errno;

	return 0;
}

int av_request(struct av_con *avc, struct av_req *avr)
{
	if (!avc || !avr)
		return EINVAL;

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
		return EINVAL;

	if (write(avc->fd, &avr->ucheck, sizeof(struct avflt_ucheck)) == -1)
		return errno;

	return 0;
}

int av_path(const char *path, int include)
{
	int fd;
	int size;
	char *buf;

	if (!path)
		return EINVAL;

	fd = open("/sys/fs/redirfs/filters/avflt/paths", O_RDWR);
	if (fd == -1)
		return errno;

	size = 4 + strlen(path) + 1;  /* 1:1:%s+0 */

	buf = malloc(sizeof(char) * size);
	if (buf) {
		close(fd);
		return ENOMEM;
	}

	memset((void *)buf, 0, size);
	snprintf(buf, size, "1:%d:%s", include ? 1 : 0, path);

	if (write(fd, buf, size) == -1) {
		close(fd);
		return errno;
	}

	close(fd);

	return 0;

}

int av_event(int event, int eon)
{
	const char *event_fn;
	int fd;

	switch (event) {
		case AV_EVENT_OPEN:
			event_fn = "/sys/fs/redirfs/filters/avflt/events/open";
			break;
		case AV_EVENT_EXEC:
			event_fn = "/sys/fs/redirfs/filters/avflt/events/close";
			break;
		case AV_EVENT_CLOSE:
			event_fn = "/sys/fs/redirfs/filters/avflt/events/open";
			break;
		case AV_EVENT_CLOSE_MODIFIED:
			event_fn = "/sys/fs/redirfs/filters/avflt/events/open";
			break;
		default:
			return EINVAL;
	}

	fd = open(event_fn, O_RDWR);
	if (fd == -1)
		return errno;

	if (write(fd, eon ? "1" : "0", 1) == -1) {
		close(fd);
		return errno;
	}

	close(fd);

	return 0;
}

int av_event_on(int event)
{
	return av_event(event, 1);
}

int av_event_off(int event)
{
	return av_event(event, 0);
}

int av_include(const char *path)
{
	return av_path(path, 1);
}

int av_exclude(const char *path)
{
	return av_path(path, 0);
}

int av_set_access(struct av_req *avr, int ava)
{
	if (!avr)
		return EINVAL;

	avr->ucheck.deny = !ava;

	return 0;
}


int av_get_filename(struct av_req *avr, const char **fn)
{
	if (!avr || !fn)
		return EINVAL;

	*fn = avr->fn;

	return 0;
}

int av_get_event(struct av_req *avr, int *event)
{
	if (!avr)
		return EINVAL;
	*event = avr->ucheck.event;

	return 0;
}

