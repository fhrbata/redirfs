#ifndef __URFS_URFS_H
#define __URFS_URFS_H

#include <linux/module.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/poll.h>
#include <linux/completion.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h>
#include "urfs_kernel.h"

#define PRINTPREFIX URFS_NAME ": "

#if 1
#define dbgmsg printk
#else
#define dbgmsg(a)
#endif

// requests

struct request{
  struct list_head list;
  unsigned long long id;
  struct completion completion;
  rfs_context context;
  struct rfs_args *args;
  enum rfs_retv retval;
};

// ufilter

struct ufilter{
  spinlock_t lock;
  rfs_filter flt;
  int id;
  struct list_head active_requests;
  struct conn *c;
  unsigned long long next_request_id;
};

void ufilter_request_add(struct ufilter *ufilter, struct request *request);
struct request *ufilter_request_get(struct ufilter *ufilter, unsigned long long request_id);
enum rfs_retv ufilter_generic_cb(rfs_context context, struct rfs_args *args);
enum rfs_err ufilter_register(struct ufilter *ufilter, char *filter_name, int priority, int active);
enum rfs_err ufilter_set_path(struct ufilter *ufilter, char *path, int flags);
enum rfs_err ufilter_unregister(struct ufilter *ufilter);
enum rfs_err ufilter_activate(struct ufilter *ufilter);
enum rfs_err ufilter_deactivate(struct ufilter *ufilter);
enum rfs_err ufilter_set_operations(struct ufilter *ufilter, struct rfs_op_info *op_info);

// msg

struct omsg_list{
  struct list_head list;
  union omsg omsg;
};
#define OMSG_LIST_ALLOC (struct omsg_list *) kmalloc(sizeof(struct omsg_list), GFP_KERNEL)
#define OMSG_LIST_FREE(omsg_list) kfree(omsg_list)

// conn

#define MAX_UFILTERS_PER_CONN 16
struct conn{
  spinlock_t lock;
  struct ufilter *ufilter[MAX_UFILTERS_PER_CONN];
  struct list_head msgs_to_send;
  wait_queue_head_t waitq;
};

int conn_alloc_ufilter(struct conn *c, int *ufilter_id);
void conn_free_ufilter(struct conn *c, int ufilter_id);
struct ufilter *conn_get_ufilter(struct conn *c, int ufilter_id);
struct conn *conn_create(void);
void conn_destroy(struct conn *c);
void conn_msg_send(struct conn *c, struct omsg_list *omsg_list);
int conn_msg_pending(struct conn *c);
struct omsg_list *conn_msg_get_next(struct conn *c);

int process_out_cmd_op_callback(struct ufilter *ufilter, struct request *request);

#endif

