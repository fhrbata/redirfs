#ifndef __LRFS_IOCTL_H__
#define __LRFS_IOCTL_H__
#include <sys/ioccom.h>

#define MAXFILTERNAME	255

struct lrfs_attach_info {
	char name[MAXFILTERNAME];
	int priority;
};

#define LRFS_ATTACH 	_IOW('L', 0, struct lrfs_attach_info) /* Attach filter */
#define LRFS_DETACH 	_IOW('L', 1, char[MAXFILTERNAME]) 	/* Detach filter */
#define LRFS_ACTIVATE 	_IOW('L', 2, char *) 	/* Activate filter */
#define LRFS_DEACTIVATE _IOW('L', 3, char *) 	/* Deactivate filter */

#endif
