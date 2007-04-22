#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <stdio.h>

#include "urfs.h"
#include "../urfs/urfs_kernel.h"

#define NODFILE "/dev/urfs"

enum urfs_err urfs_open(struct urfsconn_t *n){
  n->fd = open(NODFILE, O_RDWR);
  if (n->fd == -1){
    return(URFS_ERR_CANT_OPEN);
  }
  return(URFS_ERR_OK);
}

enum urfs_err urfs_close(struct urfsconn_t *n){
  close(n->fd);
  return(URFS_ERR_OK);
}

enum urfs_err urfs_filters_list(struct urfsconn_t *n, void **data, int *len){
  int retval;

  retval = ioctl(n->fd, URFS_CMD_GET_FILTERS_INFO_PREPARE, 0);
  
  if (retval == -1){
    return(URFS_ERR_FAIL);
  }

  if (retval == 0){
    *len = retval;
    return(URFS_ERR_OK);
  }

  *data = (void *) malloc(retval);
  if (!(*data)){
    return(URFS_ERR_NOMEM);
  }
  *len = retval;

  if (ioctl(n->fd, URFS_CMD_GET_FILTERS_INFO_DATA, *data) == -1){
    free(*data);
    return(URFS_ERR_FAIL);
  }
  return(URFS_ERR_OK);
}

enum urfs_err urfs_filter_list_paths(struct urfsconn_t *n, char *filter_name, void **data, int *len){
  int retval;
  int namememlen = strlen(filter_name) + 1;
  char msg[namememlen + sizeof(int)];
  
  memcpy(msg, &namememlen, sizeof(int));
  memcpy(msg + sizeof(int), filter_name, namememlen);
  retval = ioctl(n->fd, URFS_CMD_GET_FILTER_PATHS_INFO_PREPARE, msg);
  if (retval < 0){
    if (errno == ENODEV){
      return(URFS_ERR_NOTFOUND);
    }
    return(URFS_ERR_FAIL);
  }

  if (retval == 0){
    *len = retval;
    return(URFS_ERR_OK);
  }
 
  *data = (void *) malloc(retval);
  if (!(*data)){
    return(URFS_ERR_NOMEM);
  }
  *len = retval;

  if (ioctl(n->fd, URFS_CMD_GET_FILTER_PATHS_INFO_DATA, *data) == -1){
    free(*data);
    return(URFS_ERR_FAIL);
  }
  return(URFS_ERR_OK);
}

enum urfs_err urfs_filter_set_path(struct urfsconn_t *n, char *filter_name, char *path, int flags){
  int retval;
  int namememlen = strlen(filter_name) + 1;
  int pathmemlen = strlen(path) + 1;
  char msg[namememlen + pathmemlen + sizeof(int) * 3];
  int offset = 0;

  memcpy(msg + offset, &namememlen, sizeof(int));
  offset += sizeof(int);
  memcpy(msg + offset, filter_name, namememlen);
  offset += namememlen;
  memcpy(msg + offset, &pathmemlen, sizeof(int));
  offset += sizeof(int);
  memcpy(msg + offset, path, pathmemlen);
  offset += pathmemlen;
  memcpy(msg + offset, &flags, sizeof(int));

  retval = ioctl(n->fd, URFS_CMD_SET_FILTER_PATH, msg);
  if (retval < 0){
    if (errno == ENODEV){
      return(URFS_ERR_NOTFOUND);
    }
    return(URFS_ERR_FAIL);
  }
  return(URFS_ERR_OK);
}

enum urfs_err urfs_activate_filter(struct urfsconn_t *n, char *filter_name){
  int retval;
  int namememlen = strlen(filter_name) + 1;
  char msg[namememlen + sizeof(int)];
  
  memcpy(msg, &namememlen, sizeof(int));
  memcpy(msg + sizeof(int), filter_name, namememlen);
  retval = ioctl(n->fd, URFS_CMD_ACTIVATE_FILTER, msg);
  if (retval < 0){
    if (errno == ENODEV){
      return(URFS_ERR_NOTFOUND);
    }
    return(URFS_ERR_FAIL);
  }
  return(URFS_ERR_OK);
}

enum urfs_err urfs_deactivate_filter(struct urfsconn_t *n, char *filter_name){
  int retval;
  int namememlen = strlen(filter_name) + 1;
  char msg[namememlen + sizeof(int)];
  
  memcpy(msg, &namememlen, sizeof(int));
  memcpy(msg + sizeof(int), filter_name, namememlen);
  retval = ioctl(n->fd, URFS_CMD_DEACTIVATE_FILTER, msg);
  if (retval < 0){
    if (errno == ENODEV){
      return(URFS_ERR_NOTFOUND);
    }
    return(URFS_ERR_FAIL);
  }
  return(URFS_ERR_OK);
}

