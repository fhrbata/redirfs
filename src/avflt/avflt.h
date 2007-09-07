#if !defined(_AVFLT_H)
#define _AVFLT_H

#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/poll.h>
#include <linux/file.h>
#include <linux/mount.h>
#include "../redirfs/redirfs.h"
#include "avflt_io.h"

struct avflt_check {
	int id;
	int event;
	struct file *file;
	atomic_t deny;
	atomic_t cnt;
	atomic_t done;
	struct list_head list;
	wait_queue_head_t wait;
};


struct avflt_check *avflt_check_alloc(void);
struct avflt_check *avflt_check_get(struct avflt_check *check);
void avflt_check_put(struct avflt_check *check);
int avflt_request_queue(struct avflt_check *check);
struct avflt_check *avflt_request_dequeue(void);
void avflt_request_put(void);
int avflt_request_available_wait(void);
int avflt_request_wait(void);
int avflt_reply_queue(struct avflt_check *check);
struct avflt_check *avflt_reply_dequeue(int id);
struct avflt_check *avflt_reply_find(int id);
int avflt_reply_wait(struct avflt_check *check);
void avflt_check_start(void);
void avflt_check_stop(void);
void avflt_check_done(struct avflt_check *check);
int avflt_check_init(void);
void avflt_check_exit(void);

int avflt_pid_add(pid_t pid);
void avflt_pid_rem(pid_t pid);
pid_t avflt_pid_find(pid_t pid);

int avflt_dev_init(void);
void avflt_dev_exit(void);

int avflt_rfs_init(void);
void avflt_rfs_exit(void);
int avflt_rfs_set_ops(void);

int avflt_sys_init(struct kobject *parent);
void avflt_sys_exit(void);

struct file *avflt_get_file(struct file *file);
void avflt_put_file(struct file *file);

#endif

