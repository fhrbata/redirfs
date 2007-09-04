#if !defined(_AVFLT_IO_H)
#define _AVFLT_IO_H

#define AV_EVENT_OPEN			1
#define AV_EVENT_CLOSE			2

#define AV_CMD_GETNAME			1
#define AV_CMD_REPLY			2

#define AV_CTL_MAGIC			0xc388f
#define AV_CTL_VERSION			1

struct avflt_ucheck {
	int mag;
	int ver;
	int cmd;
	int id;
	int event;
	int deny;
	int fd;
	int fn_size;
	char *fn;
};

#endif

