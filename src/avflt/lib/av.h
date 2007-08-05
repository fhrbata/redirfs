#include "../avflt_io.h"
#include <limits.h>

#define AV_ACCESS_DENY 0
#define AV_ACCESS_ALLOW 1

struct av_con {
	int fd;
};

struct av_req {
	struct avflt_ucheck ucheck;
	char fn[PATH_MAX];
};

int av_register(struct av_con *avc);
int av_unregister(struct av_con *avc);
int av_request(struct av_con *avc, struct av_req *avr);
int av_reply(struct av_con *avc, struct av_req *avr);
int av_include(const char *path);
int av_exclude(const char *path);
int av_event_on(int event);
int av_event_off(int event);
int av_set_access(struct av_req *avr, int ava);
int av_get_filename(struct av_req *avr, const char **fn);
int av_get_event(struct av_req *avr, int *event);
