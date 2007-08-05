#if !defined(_AVFLT_IO_H)
#define _AVFLT_IO_H

#define AV_EVENT_OPEN			1
#define AV_EVENT_CLOSE			2
#define AV_EVENT_EXEC			3
#define AV_EVENT_CLOSE_MODIFIED		4

#define AV_CTL_MAGIC			0xc388f
#define AV_CTL_VERSION			1

struct avflt_ucheck {
	int mag;
	int ver;
	int id;
	int event;
	int deny;
	int fn_size;
	char *fn;
};

#endif

