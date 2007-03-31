#ifndef _RFS_DEBUG_H
#define _RFS_DEBUG_H

#include <linux/module.h>

#ifdef RFS_DEBUG

#define rfs_debug(format, args...) \
	do {\
		printk(KERN_ALERT format, ## args); \
	} while (0)

#else

#define rfs_debug(format, args...) do {} while(0)

#endif /* RFS_DEBUG */

#endif /* _RFS_DEBUG_H */
