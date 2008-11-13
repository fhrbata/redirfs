#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include "av.h"


int av_register(struct av_connection *conn)
{
	if (!conn) {
		errno = EINVAL;
		return -1;
	}

	if ((conn->fd = open("/dev/avflt", O_RDWR)) == -1)
		return -1;

	return 0;
}

int av_unregister(struct av_connection *conn)
{
	if (!conn) {
		errno = EINVAL;
		return -1;
	}

	if (close(conn->fd) == -1)
		return -1;

	return 0;
}

int av_request(struct av_connection *conn, struct av_event *event)
{
	char buf[256];

	if (!conn || !event) {
		errno = EINVAL;
		return -1;
	}

	if (read(conn->fd, buf, 256) == -1)
		return -1;

	if (sscanf(buf, "id:%d,type:%d,fd:%d,pid:%d,tgid:%d",
				&event->id, &event->type, &event->fd,
				&event->pid, &event->tgid) != 5)
		return -1;

	event->res = 0;

	return 0;
}

int av_reply(struct av_connection *conn, struct av_event *event)
{
	char buf[256];

	if (!conn || !event) {
		errno = EINVAL;
		return -1;
	}

	snprintf(buf, 256, "id:%d,res:%d", event->id, event->res);

	if (write(conn->fd, buf, strlen(buf) + 1) == -1)
		return -1;

	if (close(event->fd) == -1)
		return -1;

	return 0;
}

int av_set_result(struct av_event *event, int res)
{
	if (!event) {
		errno = EINVAL;
		return -1;
	}

	if (res != AV_ACCESS_ALLOW || res != AV_ACCESS_DENY) {
		event->res = res;
	}

	return 0;
}

int av_get_filename(struct av_event *event, char *buf, int size)
{
	char fn[256];

	memset(fn, 0, 256);
	memset(buf, 0, size);
	snprintf(fn, 255, "/proc/%d/fd/%d", getpid(), event->fd);

	if (readlink(fn, buf, size - 1) == -1)
		return -1;

	return 0;
}

