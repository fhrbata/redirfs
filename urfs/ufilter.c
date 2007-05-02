#include "urfs.h"

void ufilter_request_add(struct ufilter *ufilter, struct request *request){
  INIT_LIST_HEAD(&request->list);
  spin_lock(&ufilter->lock); 
  list_add_tail(&request->list, &ufilter->active_requests);
  spin_unlock(&ufilter->lock);
}

struct request *ufilter_request_get(struct ufilter *ufilter, unsigned long long request_id){
  struct list_head *ptr;
  struct request *request;
  struct request *retval = NULL;

  list_for_each(ptr, &ufilter->active_requests){
    request = list_entry(ptr, struct request, list);
    if (request->id == request_id){
      list_del(ptr);
      retval = request;
      break;
    }
  }
  return(retval);
}

unsigned long long ufilter_get_uniqeue_request_id(struct ufilter *ufilter){
  return((ufilter->next_request_id)++);
}

enum rfs_retv ufilter_generic_cb(rfs_context context, struct rfs_args *args){
  struct ufilter *ufilter;
  struct conn *c;
  struct request *request;
  int err;
  enum rfs_retv retval = RFS_CONTINUE;

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

  request = (struct request *) kmalloc(sizeof(struct request), GFP_ATOMIC);
  if (!request){
    goto end;
  }

  init_completion(&request->completion);
  request->id = ufilter_get_uniqeue_request_id(ufilter);
  dbgmsg(PRINTPREFIX "request id: %llu\n", request->id);
  request->context = context;
  request->args = args;
 
  err = process_out_cmd_op_callback(ufilter, request);
  if (err){
    goto free_request;
  }

  dbgmsg(PRINTPREFIX "waiting for completion\n");
  wait_for_completion(&request->completion);
  dbgmsg(PRINTPREFIX "complete\n");
  retval = request->retval;
  
free_request:
  kfree(request);

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

