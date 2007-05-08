// user filter doing simple scrambling crypting (swapping nibbles)

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../../urfs.h"

void scramble(char *buf, size_t count){
  size_t i;

  for(i = 0; i < count; i++){
    buf[i] = ((buf[i] << 4) & 0xF0) | ((buf[i] >> 4) & 0x0F); // swap nibbles
  }
}

enum rfs_retv scrambleflt_read(rfs_context context, struct rfs_args *args){
  //printf("read %s\n", args->type.call == RFS_PRECALL ? "precall" : "postcall");
  scramble(args->args.f_read.buf, args->retv.rv_ssize);
  return(RFS_CONTINUE);
}

enum rfs_retv scrambleflt_write(rfs_context context, struct rfs_args *args){
  //printf("write %s\n", args->type.call == RFS_PRECALL ? "precall" : "postcall");
  scramble(args->args.f_write.buf, args->args.f_write.count);
  return(RFS_CONTINUE);
}

static struct rfs_op_info op_info[] = {
  {RFS_REG_FOP_READ, NULL, scrambleflt_read},
  {RFS_REG_FOP_WRITE, scrambleflt_write, NULL},
  {RFS_OP_END, NULL, NULL}
};

int main(int argc, char *argv[]){
  struct urfs_conn c;
  int err;
  rfs_filter flt;
  struct rfs_filter_info filter_info = {"scrambleftl", 13, 0};
  struct rfs_path_info path_info = {"/tmp/scramble", RFS_PATH_INCLUDE | RFS_PATH_SUBTREE};

  err = urfs_open(&c);
  if (err){
    printf("can't open nodfile\n");
    return(1);
  }
  if (urfs_filter_alloc(&flt, &c)){
    printf("cannot alloc filter\n");
    goto close;
  }

  err = rfs_register_filter(&flt, &filter_info);
  if (err){
    printf("rfs_register_filter failed: %d\n", err);
    goto free_filter;
  }
  
  err = rfs_set_operations(flt, op_info);
  if (err){
    printf("rfs_set_operations failed: %d\n", err);
    goto free_filter;
  }

  err = rfs_set_path(flt, &path_info);
  if (err){
    printf("rfs_set_path failed: %d\n", err);
    goto free_filter;
  }

  err = rfs_activate_filter(flt);
  if (err){
    printf("rfs_activate_filter failed: %d\n", err);
    goto free_filter;
  }
  
  err = urfs_main(&c, flt);
  if (err){
    printf("urfs_main failed: %d - %s\n", err, strerror(errno));
    goto free_filter;
  }

  err = rfs_deactivate_filter(flt);
  if (err){
    printf("rfs_deactivate_filter failed: %d\n", err);
    goto free_filter;
  }
  
  err = rfs_unregister_filter(flt);
  if (err){
    printf("rfs_unregister_filter failed: %d\n", err);
    goto free_filter;
  }

free_filter:
  urfs_filter_free(flt);

close:
  urfs_close(&c);
  return(0);
}
