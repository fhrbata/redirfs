#ifndef _REDIRFS_DEBUG_H
#define _REDIRFS_DEBUG_H

#include <linux/module.h>

#ifdef REDIRFS_DEBUG

#define redirfs_debug(format, args...) \
	do {\
		printk(KERN_ALERT "RedirFS DEBUG: %d [%s:%d] %s: ", \
				current->pid, __FILE__, __LINE__, __FUNCTION__);\
		printk(KERN_ALERT format "\n", ## args); \
	} while (0)

#else

#define redirfs_debug(format, args...) do {} while(0)

#endif /* REDIRFS_DEBUG */

#endif /* _REDIRFS_DEBUG_H */
