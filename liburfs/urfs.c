#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <stdio.h>

#include "urfs.h"
#include "../urfs/urfs_kernel.h"

#define NODFILE "/dev/" URFS_NAME

int urfs_open(struct urfs_conn *c){
  c->fd = open(NODFILE, O_RDWR);
  if (c->fd >= 0){
    return(0);
  }
  memset(&c->filters, 0, sizeof(struct urfs_filter *) * MAX_UFILTERS_PER_CONN);
  return(c->fd);
}

void urfs_close(struct urfs_conn *c){
  close(c->fd);
}

int urfs_filter_alloc(rfs_filter *filter, struct urfs_conn *c){
  struct urfs_filter *flt;

  *filter = malloc(sizeof(struct urfs_filter));
  if (!(*filter)){
    return(-1);
  }
  flt = (struct urfs_filter *) *filter;
  flt->conn = c;
  return(0);
}

void urfs_filter_free(rfs_filter filter){
  if (filter){
    free(filter);
  }
}

static int wait_for_msg(struct urfs_conn *c){
  fd_set inp;
  int max_fd;
  int sel;
  int fd = c->fd;
  
  while(1){
    FD_ZERO(&inp);
    FD_SET(fd, &inp);
    max_fd = fd + 1;
    sel = select(max_fd, &inp, NULL, NULL, NULL);
    if (sel < 0){
      return(sel);
    }
    else if (FD_ISSET(fd, &inp)){
      return(0);
    }
  }
}

static int imsg_send(struct urfs_conn *c, union imsg *msg){
  int len = sizeof(union imsg);
  int err;

  err = write(c->fd, msg, len);
  if (err != len){
    return(err);
  }
  return(0);
}

static int omsg_recv(struct urfs_conn *c, union omsg *msg){
  int len = sizeof(union omsg);
  int err;

  err = read(c->fd, msg, len);
  if (err != len){
    return(err);
  }
  return(0);
}

static int send_and_receive(struct urfs_conn *c, union imsg *imsg, union omsg *omsg){
  int err;
  
  err = imsg_send(c, imsg);
  if (err){
    return(err);
  }
  if (wait_for_msg(c)){
    return(err);
  }
  err = omsg_recv(c, omsg);
  if (err){
    return(err);
  }
  return(0);
}

static int switch_callbacks(struct urfs_conn *c, int enable){
  union imsg imsg;
  union omsg omsg;
  int err;
  
  imsg.cmd = URFS_CMD_CONN_SWITCH_CALLBACKS;
  imsg.conn_switch_callbacks.enable = enable;
  err = send_and_receive(c, &imsg, &omsg);
  if (err){
    return(err);
  }
  return(0);
}

#define enable_callbacks(c) switch_callbacks(c, 1)
#define disable_callbacks(c) switch_callbacks(c, 0)

static int get_args(struct urfs_conn *c, int ufilter_id, unsigned long long request_id, struct rfs_args *args, unsigned char *str){
  union imsg imsg;
  union omsg omsg;
  int err;

  imsg.cmd = URFS_CMD_OP_CALLBACK_GET_ARGS;
  imsg.op_callback_get_args.ufilter_id = ufilter_id;
  imsg.op_callback_get_args.request_id = request_id;
  imsg.op_callback_get_args.args = args;
  imsg.op_callback_get_args.str = str;
  err = send_and_receive(c, &imsg, &omsg);
  if (err){
    return(err);
  }
  return(0);
}

int urfs_main(struct urfs_conn *c, rfs_filter filter){
  struct urfs_filter *flt;
  union imsg imsg;
  union omsg omsg;
  int err;
  struct rfs_args args;
  unsigned char str[1024];
  int ufilter_id;
  unsigned long long request_id;
  enum rfs_retv (**ops)(rfs_context, struct rfs_args *);
  enum rfs_retv (*op)(rfs_context, struct rfs_args *);
  enum rfs_retv retv;

  flt = (struct urfs_filter *) filter;
  if (!flt){
    return(-1);
  }

  err = enable_callbacks(c);
  if (err){
    return(err);
  }

  for(;;){
    if (wait_for_msg(c)){
      return(-EINVAL);
    }
    err = omsg_recv(c, &omsg);
    if (err){
      goto disable_callbacks;
    }
    if (omsg.cmd == URFS_CMD_OP_CALLBACK){
      ufilter_id = omsg.op_callback.ufilter_id;
      request_id = omsg.op_callback.request_id;
      // printf("event ufilter id: %d, request id: %llu\n", ufilter_id, request_id);
      if (!get_args(c, ufilter_id, request_id, &args, str)){
        if (c->filters[ufilter_id] != NULL){
	  if (args.type.call == RFS_PRECALL){
	    ops = c->filters[ufilter_id]->f_pre_cbs;
	    op = ops[args.type.id];
	    if (op){
	      retv = op(NULL, &args);
	    }
	  }
	  else if (args.type.call == RFS_POSTCALL){
            ops = c->filters[ufilter_id]->f_pre_cbs;
	    op = ops[args.type.id];
	    if (op){
	      retv = op(NULL, &args);
	    }
	  }
	}
      }
      imsg.op_callback.cmd = omsg.op_callback.cmd;
      imsg.op_callback.ufilter_id = ufilter_id;
      imsg.op_callback.request_id = request_id;
      imsg.op_callback.retval = retv;
      err = imsg_send(c, &imsg);
      if (err){
        printf("xxx\n");
        goto disable_callbacks;
      }
    }
  }

disable_callbacks:
  disable_callbacks(c);

  return(err);
}

enum rfs_err rfs_register_filter(rfs_filter *filter, struct rfs_filter_info *filter_info){
  struct urfs_filter *flt;
  struct urfs_conn *c;
  union imsg imsg;
  union omsg omsg;
  int err;
  enum rfs_retv (*op)(rfs_context, struct rfs_args *);

  if (!filter_info || !filter_info->name){
    return(RFS_ERR_INVAL);
  }
  flt = (struct urfs_filter *) *filter;
  if (!flt){
    return(RFS_ERR_INVAL);
  }
  c = flt->conn;
  if (!c){
    return(RFS_ERR_INVAL);
  }

  imsg.cmd = URFS_CMD_FILTER_REGISTER;
  imsg.filter_register.filter_name_memlen = strlen(filter_info->name) + 1;
  imsg.filter_register.filter_info = filter_info;
  err = send_and_receive(c, &imsg, &omsg);
  if (err){
    return(RFS_ERR_INVAL);
  }
  if (omsg.filter_register.err == RFS_ERR_OK){
    flt->id = omsg.filter_register.ufilter_id;
    c->filters[flt->id] = flt;
    memset(&flt->f_pre_cbs, 0, sizeof(op) * RFS_OP_END);
    memset(&flt->f_post_cbs, 0, sizeof(op) * RFS_OP_END);
    flt->mod_cb = NULL;
  }
  return(omsg.filter_register.err);
}

enum rfs_err rfs_unregister_filter(rfs_filter filter){
  struct urfs_filter *flt;
  struct urfs_conn *c;
  union imsg imsg;
  union omsg omsg;
  int err;

  flt = (struct urfs_filter *) filter;
  if (!flt){
    return(RFS_ERR_INVAL);
  }
  c = flt->conn;
  if (!c){
    return(RFS_ERR_INVAL);
  }

  imsg.cmd = URFS_CMD_FILTER_UNREGISTER;
  imsg.filter_unregister.ufilter_id = flt->id;
  err = send_and_receive(c, &imsg, &omsg);
  if (err){
    return(RFS_ERR_INVAL);
  }
  c->filters[flt->id] = NULL;
  return(omsg.filter_unregister.err);
}

enum rfs_err rfs_activate_filter(rfs_filter filter){
  struct urfs_filter *flt;
  struct urfs_conn *c;
  union imsg imsg;
  union omsg omsg;
  int err;

  flt = (struct urfs_filter *) filter;
  if (!flt){
    return(RFS_ERR_INVAL);
  }
  c = flt->conn;
  if (!c){
    return(RFS_ERR_INVAL);
  }

  imsg.cmd = URFS_CMD_FILTER_ACTIVATE;
  imsg.filter_activate.ufilter_id = flt->id;
  err = send_and_receive(c, &imsg, &omsg);
  if (err){
    return(RFS_ERR_INVAL);
  }
  return(omsg.filter_activate.err);
}

enum rfs_err rfs_deactivate_filter(rfs_filter filter){
  struct urfs_filter *flt;
  struct urfs_conn *c;
  union imsg imsg;
  union omsg omsg;
  int err;

  flt = (struct urfs_filter *) filter;
  if (!flt){
    return(RFS_ERR_INVAL);
  }
  c = flt->conn;
  if (!c){
    return(RFS_ERR_INVAL);
  }

  imsg.cmd = URFS_CMD_FILTER_DEACTIVATE;
  imsg.filter_deactivate.ufilter_id = flt->id;
  err = send_and_receive(c, &imsg, &omsg);
  if (err){
    return(RFS_ERR_INVAL);
  }
  return(omsg.filter_deactivate.err);
}

enum rfs_err rfs_set_path(rfs_filter filter, struct rfs_path_info *path_info){
  struct urfs_filter *flt;
  struct urfs_conn *c;
  union imsg imsg;
  union omsg omsg;
  int err;

  if (!path_info || !path_info->path){
    return(RFS_ERR_INVAL);
  }
  flt = (struct urfs_filter *) filter;
  if (!flt){
    return(RFS_ERR_INVAL);
  }
  c = flt->conn;
  if (!c){
    return(RFS_ERR_INVAL);
  }

  imsg.cmd = URFS_CMD_FILTER_SET_PATH;
  imsg.filter_set_path.ufilter_id = flt->id;
  imsg.filter_set_path.path_memlen = strlen(path_info->path) + 1;
  imsg.filter_set_path.path_info = path_info;
  err = send_and_receive(c, &imsg, &omsg);
  if (err){
    return(RFS_ERR_INVAL);
  }
  return(omsg.filter_set_path.err);
}

enum rfs_err rfs_set_operations(rfs_filter filter, struct rfs_op_info *op_info){
  struct urfs_filter *flt;
  struct urfs_conn *c;
  union imsg imsg;
  union omsg omsg;
  int err;
  char ops_call_flags[RFS_OP_END];
  char flags;
  int i;
  enum rfs_retv (*op)(rfs_context, struct rfs_args *);

  if (!op_info){
    return(RFS_ERR_INVAL);
  }
  flt = (struct urfs_filter *) filter;
  if (!flt){
    return(RFS_ERR_INVAL);
  }
  c = flt->conn;
  if (!c){
    return(RFS_ERR_INVAL);
  }

  memset(ops_call_flags, 0, sizeof(ops_call_flags));
  for(i = 0; op_info[i].op_id != RFS_OP_END; i++){
    flags = 0;
    if (op_info[i].pre_cb){
      flags |= PRE_CALL_FLAG;
    }
    if (op_info[i].post_cb){
      flags |= POST_CALL_FLAG;
    }
    ops_call_flags[op_info[i].op_id] = flags;
  }

  imsg.cmd = URFS_CMD_FILTER_SET_OPERATIONS;
  imsg.filter_set_operations.ufilter_id = flt->id;
  imsg.filter_set_operations.ops_call_flags = ops_call_flags;
  err = send_and_receive(c, &imsg, &omsg);
  if (err){
    return(RFS_ERR_INVAL);
  }
  if (omsg.filter_set_operations.err == RFS_ERR_OK){
    memset(&flt->f_pre_cbs, 0, sizeof(op) * RFS_OP_END);
    memset(&flt->f_post_cbs, 0, sizeof(op) * RFS_OP_END);
    for(i = 0; op_info[i].op_id != RFS_OP_END; i++){
      flt->f_pre_cbs[op_info[i].op_id] = op_info[i].pre_cb;
      flt->f_post_cbs[op_info[i].op_id] = op_info[i].post_cb;
    }
  }
  return(omsg.filter_set_operations.err);
}

