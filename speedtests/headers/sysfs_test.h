#ifndef _SYSFS_TEST_H
#define _SYSFS_TEST_H

#define GETNUMOFPAGES(len, page_size) ((len) / page_size + ((len) % page_size == 0 ? 0 : 1))

#endif
