#ifndef __URFS_H
#define __URFS_H

#include <errno.h>
#include "../urfs/urfs_kernel.h"

struct urfs_conn{
  int fd;
};

struct urfs_filter{
  int id;
  struct urfs_conn *conn;
  enum rfs_retv (*f_pre_cbs[RFS_OP_END])(rfs_context, struct rfs_args *);
  enum rfs_retv (*f_post_cbs[RFS_OP_END])(rfs_context, struct rfs_args *);
  int (*mod_cb)(union rfs_mod *);
};

int urfs_open(struct urfs_conn *n);
void urfs_close(struct urfs_conn *n);
int urfs_filter_alloc(rfs_filter *filter, struct urfs_conn *c);
void urfs_filter_free(rfs_filter filter);

#endif

