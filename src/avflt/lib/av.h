#include "../avflt_io.h"
#include <limits.h>


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
int av_access(struct av_con *avc, struct av_req *avr, int ava);
int av_include(const char *path);
int av_exclude(const char *path);
