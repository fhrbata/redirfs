#include "urfs.h"

void ufilter_request_add(struct ufilter *ufilter, struct request *request){
  INIT_LIST_HEAD(&request->list);
  spin_lock(&ufilter->lock); 
  list_add_tail(&request->list, &ufilter->active_requests);
  dbgmsg(PRINTPREFIX "adding request with id: %llu\n", request->id);
  spin_unlock(&ufilter->lock);
}

struct request *ufilter_request_get(struct ufilter *ufilter, unsigned long long request_id, int del){
  struct request *request;
  struct request *retval = NULL;

  spin_lock(&ufilter->lock); 
  list_for_each_entry(request, &ufilter->active_requests, list){
    if (request->id == request_id){
      retval = request;
      break;
    }
  }
  if (retval && del){
    list_del(&retval->list);
  }
  spin_unlock(&ufilter->lock);
  return(retval);
}

static unsigned long long ufilter_get_unique_request_id(struct ufilter *ufilter){
  unsigned long long retval;
  
  spin_lock(&ufilter->lock); 
  retval = (ufilter->next_request_id)++;
  spin_unlock(&ufilter->lock);
  return(retval);
}

enum rfs_retv ufilter_generic_cb(rfs_context context, struct rfs_args *args){
  struct ufilter *ufilter;
  struct conn *c;
  struct request *request;
  int err;
  enum rfs_retv retval = RFS_CONTINUE;
  unsigned char *buf;

  if (rfs_get_context_flt_private_data(context, (void **) &ufilter)){
    goto end;
  }
  if (!ufilter){
    goto end;
  }
  c = ufilter->c;
  if (!c){
    goto end;
  }

  dbgmsg(PRINTPREFIX "generic callback called for ufilter %d\n", ufilter->id);

  if (!conn_enabled_callbacks(c)){
    dbgmsg(PRINTPREFIX "callbacks disabled\n");
    goto end;
  }

  request = request_create(ufilter_get_unique_request_id(ufilter));
  dbgmsg(PRINTPREFIX "request id: %llu\n", request->id);
  request->data.op_callback.context = NULL;
  request->data.op_callback.args = args;
 
  // in case of read and write we need to copy buffer from original user space to kernel
  switch (args->type.id){
    case RFS_REG_FOP_READ:
      buf = kmalloc(args->args.f_read.count, GFP_ATOMIC);
      if (!buf){
        goto destroy_request;
      }
      if (copy_from_user(buf, args->args.f_read.buf, args->args.f_read.count)){
        goto destroy_request;
      }
      request->data.op_callback.buf = buf;
      break;
    case RFS_REG_FOP_WRITE:
      buf = kmalloc(args->args.f_write.count, GFP_ATOMIC);
      if (!buf){
        goto destroy_request;
      }
      if (copy_from_user(buf, args->args.f_write.buf, args->args.f_write.count)){
        goto destroy_request;
      }
      request->data.op_callback.buf = buf;
      break;
    default:
      break;
  }

  err = process_out_cmd_op_callback(ufilter, request);
  if (err){
    goto destroy_request;
  }

  dbgmsg(PRINTPREFIX "waiting for completion\n");
  wait_for_completion(&request->completion);
  dbgmsg(PRINTPREFIX "complete request_id: %llu\n", request->id);
  retval = request->data.op_callback.retval;

  // in case of read and write we need to copy buffer back to original userspace
  switch (args->type.id){
    case RFS_REG_FOP_READ:
      if (copy_to_user(args->args.f_read.buf, request->data.op_callback.buf, args->args.f_read.count)){
        goto destroy_request;
      }
      kfree(request->data.op_callback.buf);
      break;
    case RFS_REG_FOP_WRITE:
      if (copy_to_user(args->args.f_write.buf, request->data.op_callback.buf, args->args.f_write.count)){
        goto destroy_request;
      }
      kfree(request->data.op_callback.buf);
      break;
    default:
      break;
  }
  
destroy_request:
  request_destroy(request);

end:
  return(retval);
}

enum rfs_err ufilter_register(struct ufilter *ufilter, char *filter_name, int priority, int active){
  struct rfs_filter_info info;
  enum rfs_err err;
  rfs_filter flt;

  info.name = filter_name;
  info.priority = priority;
  info.active = active;
  err = rfs_register_filter(&flt, &info);
  if (err == RFS_ERR_OK){
    ufilter->flt = flt;
    ufilter->next_request_id = 0;
    ufilter->lock = SPIN_LOCK_UNLOCKED;
    spin_lock(&ufilter->lock);
    INIT_LIST_HEAD(&ufilter->active_requests);
    spin_unlock(&ufilter->lock);
    err = rfs_set_private_data(flt, ufilter);
  }
  return(err);
}

enum rfs_err ufilter_set_path(struct ufilter *ufilter, char *path, int flags){
  struct rfs_path_info info;
  enum rfs_err err;

  info.path = path;
  info.flags = flags;
  err = rfs_set_path(ufilter->flt, &info);
  return(err);
}

enum rfs_err ufilter_unregister(struct ufilter *ufilter){
  enum rfs_err err;

  err = rfs_unregister_filter(ufilter->flt);
  return(err);
}

enum rfs_err ufilter_activate(struct ufilter *ufilter){
  enum rfs_err err;

  err = rfs_activate_filter(ufilter->flt);
  return(err);
}

enum rfs_err ufilter_deactivate(struct ufilter *ufilter){
  enum rfs_err err;

  err = rfs_deactivate_filter(ufilter->flt);
  return(err);
}

enum rfs_err ufilter_set_operations(struct ufilter *ufilter, struct rfs_op_info *op_info){
  enum rfs_err err;

  err = rfs_set_operations(ufilter->flt, op_info);
  return(err);
}

