#ifndef __URFS_URFS_KERNEL_H
#define __URFS_URFS_KERNEL_H

#include <linux/fs.h>
#include <linux/dcache.h>

#define MAX_UFILTERS_PER_CONN 16

struct urfs_str{
  unsigned int len;
  unsigned char *name;
};

struct urfs_inode{
  umode_t i_mode;
};

struct urfs_dentry{
  struct urfs_str d_name;
};

struct urfs_nameidata{
  struct urfs_dentry __dentry;
  struct urfs_dentry *dentry;
};

struct urfs_file{
  struct urfs_dentry __f_dentry;
  struct urfs_dentry *f_dentry;
};

union urfs_op_args{
  struct {
    struct urfs_inode __inode;
    struct urfs_inode *inode;
    int mask;
    struct urfs_nameidata __nd;
    struct urfs_nameidata *nd;
  } i_permission;	
  struct {
    struct urfs_inode __inode;
    struct urfs_inode *inode;
    struct urfs_file __file;
    struct urfs_file *file;
  } f_open;
};

union urfs_op_retv{
};

#define __RFS_OP_TYPE_ONLY
#include "../../../trunk/src/redirfs/redirfs.h"
#undef __RFS_OP_TYPE_ONLY

#ifdef __KERNEL__
struct urfs_args{ // need to have userspace args struct in kernel by different name
#else
struct rfs_args{
#endif
  union urfs_op_args args;
  union urfs_op_retv retv;
  struct rfs_op_type type;
};

#define __NO_RFS_OP_TYPE
#include "../../../trunk/src/redirfs/redirfs.h"
#undef __NO_RFS_OP_TYPE

#define URFS_NAME "urfs"

// commands
enum urfs_cmd{
  URFS_CMD_FILTER_REGISTER = 0,
  URFS_CMD_FILTER_UNREGISTER = 1,
  URFS_CMD_FILTER_SET_PATH = 2,
  URFS_CMD_FILTER_ACTIVATE = 3,
  URFS_CMD_FILTER_DEACTIVATE = 4,
  URFS_CMD_FILTER_SET_OPERATIONS = 5,
  URFS_CMD_CONN_SWITCH_CALLBACKS = 6,
  URFS_CMD_OP_CALLBACK = 7,
  URFS_CMD_OP_CALLBACK_GET_ARGS = 8,
};

// calls flags

#define PRE_CALL_FLAG	(1 << 0)
#define POST_CALL_FLAG	(1 << 1)

union imsg{
  char cmd;
  struct {
    char cmd;
    int filter_name_memlen;
#ifdef __KERNEL__
    struct rfs_filter_info __user *filter_info;
#else
    struct rfs_filter_info *filter_info;
#endif
  } filter_register;
  struct {
    char cmd;
    int ufilter_id;
  } filter_unregister;
  struct {
    char cmd;
    int ufilter_id;
  } filter_activate;
  struct {
    char cmd;
    int ufilter_id;
  } filter_deactivate;
  struct {
    char cmd;
    int ufilter_id;
    int path_memlen;
#ifdef __KERNEL__
    struct rfs_path_info __user *path_info;
#else
    struct rfs_path_info *path_info;
#endif
  } filter_set_path;
  struct {
    char cmd;
    int ufilter_id;
#ifdef __KERNEL__
    char __user *ops_call_flags;
#else
    char *ops_call_flags;
#endif
  } filter_set_operations;
  struct {
    char cmd;
    int enable;
  } conn_switch_callbacks;
  struct {
    char cmd;
    int ufilter_id;
    unsigned long long request_id;
    enum rfs_retv retval;
  } op_callback;
  struct {
    char cmd;
    int ufilter_id;
    unsigned long long request_id;
#ifdef __KERNEL__
    struct urfs_args __user *args;
    unsigned char __user *str;
#else
    struct rfs_args *args;
    unsigned char *str;
#endif
  } op_callback_get_args;
};

union omsg{
  char cmd;
  struct {
    char cmd;
    enum rfs_err err;
    int ufilter_id;
  } filter_register;
  struct {
    char cmd;
    enum rfs_err err;
  } filter_unregister;
  struct {
    char cmd;
    enum rfs_err err;
  } filter_activate;
  struct {
    char cmd;
    enum rfs_err err;
  } filter_deactivate;
  struct {
    char cmd;
    enum rfs_err err;
  } filter_set_path;
  struct {
    char cmd;
    enum rfs_err err;
  } filter_set_operations;
  struct {
    char cmd;
  } conn_switch_callbacks;
  struct {
    char cmd;
    int ufilter_id;
    unsigned long long request_id;
#ifdef __KERNEL__
    rfs_context __user context;
    struct rfs_args __user *args;
#else
    rfs_context context;
    struct rfs_args *args;
#endif
  } op_callback;
    struct {
    char cmd;
    enum rfs_err err;
  } op_callback_get_args;
};

#endif

