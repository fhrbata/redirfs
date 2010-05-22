#ifndef __LAREFSDEV_H__
#define __LAREFSDEV_H__

#define MAX_FLT_SIZE		(LAREFS_BOTTOM + sizeof(filter_op_names) + \
				sizeof(flt_cap) + sizeof(finfo_cap))

#define MAX_FINFO_SIZE		(MAXPATHLEN + sizeof(flt_cap) + sizeof(finfo_cap))

char *filter_op_names[LAREFS_BOTTOM] = {
	"Access",
	"Accessx",
	"Getattr",
	"Inactive",
	"Lookup",
	"Open",
	"Rename",
	"Setattr",
	"Ioctl"
};

#endif
