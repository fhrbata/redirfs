#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include <stdio.h>

#include "../redirfs/redirfs.h"

/* file descriptor for nodfile - global all over the program */
int fd;

int redirctl_filters_list(void){
  int retval;
  void *data;
  int len;
  int offset;
  int namememlen;
  char *name;
  int priority;
  int active;

  retval = ioctl(fd, REDIRCTL_CMD_GET_FILTERS_INFO_PREPARE, 0);
  
  if (retval == -1){
    printf("get filters info prepare failed\n");
    return(-1);
  }

  if (retval == 0){
    printf("no filter inserted\n");
    return(-2);
  }

  data = (void *) malloc(retval);
  if (!data){
    printf("data malloc failed\n");
    return(-3);
  }
  len = retval;

  if (ioctl(fd, REDIRCTL_CMD_GET_FILTERS_INFO_DATA, data) == -1){
    printf("get filters info data failed\n");
    free(data);
    return(-4);
  }

  offset = 0;
  while(len - offset > 0){
    namememlen = *((int *) (data + offset));
    offset += sizeof(int);
    name = (char *) (data + offset);
    offset += namememlen;
    priority = *((int *) (data + offset));
    offset += sizeof(int);
    active = *((int *) (data + offset));
    offset += sizeof(int);
    printf("%s %d %d\n", name, priority, active);
  }
  free(data);
  
  return(0);
}

int redirctl_filter_list_paths(char *filter_name){
  int retval;
  int namememlen = strlen(filter_name) + 1;
  char msg[namememlen + sizeof(int)];
  void *data;
  int len;
  int offset;
  int pathmemlen;
  char *path;
  int flags;

  memcpy(msg, &namememlen, sizeof(int));
  memcpy(msg + sizeof(int), filter_name, namememlen);
  retval = ioctl(fd, REDIRCTL_CMD_GET_FILTER_PATHS_INFO_PREPARE, msg);
  if (retval < 0){
    if (errno == ENODEV){
      printf("filter named \"%s\" not found\n", filter_name);
      return(-1);
    }
    printf("get filter paths info prepare failed\n");
    return(-2);
  }

  if (retval == 0){
    printf("no paths set to this filter\n");
    return(-3);
  }
 
  data = (void *) malloc(retval);
  if (!data){
    printf("data malloc failed\n");
    return(-4);
  }
  len = retval;

  if (ioctl(fd, REDIRCTL_CMD_GET_FILTER_PATHS_INFO_DATA, data) == -1){
    printf("get filter paths info data failed\n");
    free(data);
    return(-5);
  }
  
  offset = 0;
  while(len - offset > 0){
    pathmemlen = *((int *) (data + offset));
    offset += sizeof(int);
    path = (char *) (data + offset);
    offset += pathmemlen;
    flags = *((int *) (data + offset));
    offset += sizeof(int);
    printf("%s 0x%04X\n", path, flags);
  }
  free(data);

  return(0);
}

int redirctl_filter_set_path(char *filter_name, char *path, int flags){
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

  retval = ioctl(fd, REDIRCTL_CMD_SET_FILTER_PATH, msg);
  if (retval < 0){
    if (errno == ENODEV){
      printf("filter named \"%s\" not found\n", filter_name);
      return(-1);
    }
    else if (errno = EOPNOTSUPP){
      printf("operation not permitted\n");
      return(-2);
    }
    printf("set filter path failed\n");
    return(-3);
  }

  return(0);
}

int redirctl_activate_filter(char *filter_name){
  int retval;
  int namememlen = strlen(filter_name) + 1;
  char msg[namememlen + sizeof(int)];
  
  memcpy(msg, &namememlen, sizeof(int));
  memcpy(msg + sizeof(int), filter_name, namememlen);
  retval = ioctl(fd, REDIRCTL_CMD_ACTIVATE_FILTER, msg);
  if (retval < 0){
    if (errno == ENODEV){
      printf("filter named \"%s\" not found\n", filter_name);
      return(-1);
    }
    else if (errno = EOPNOTSUPP){
      printf("operation not permitted\n");
      return(-2);
    }
    printf("activate filter failed\n");
    return(-3);
  }
  return(0);
}

int redirctl_deactivate_filter(char *filter_name){
  int retval;
  int namememlen = strlen(filter_name) + 1;
  char msg[namememlen + sizeof(int)];
  
  memcpy(msg, &namememlen, sizeof(int));
  memcpy(msg + sizeof(int), filter_name, namememlen);
  retval = ioctl(fd, REDIRCTL_CMD_DEACTIVATE_FILTER, msg);
  if (retval < 0){
    if (errno == ENODEV){
      printf("filter named \"%s\" not found\n", filter_name);
      return(-1);;
    }
    else if (errno = EOPNOTSUPP){
      printf("operation not permitted\n");
      return(-2);
    }
    printf("set filter path failed\n");
    return(-3);
  }
}

void usage(void){
  printf("usage: redirctl [command] [options]\n"
         "commands:\n"
	 "  list\n"
	 "  paths filter_name\n"
	 "  setpath filter_name path [include|exclude] [single|subtree]\n"
	 "  activate filter_name\n"
	 "  deactivate filter_name\n");
}

int main(int argc, char *argv[]){
  int retval = 0;

  if (argc < 2){
    usage();
    return(1);
  }

  if ((fd = open("/dev/" REDIRCTL_NAME, O_RDWR)) == -1){
    printf("cannot open redirctl device - check for /dev/" REDIRCTL_NAME " file presence!\n");
    return(2);
  }

  if (strcmp(argv[1], "list") == 0){
    if (redirctl_filters_list() != 0){
      retval = 3;
      goto end;
    }
  }
  else if (strcmp(argv[1], "paths") == 0){
    if (argc < 3){
      usage();
      retval = 1;
      goto end;
    }
    if (redirctl_filter_list_paths(argv[2]) != 0){
      retval = 3;
      goto end;
    }

  }
  else if (strcmp(argv[1], "setpath") == 0){
    int flags = 0;
    
    if (argc < 6){
      usage();
      retval = 1;
      goto end;
    }

    if (strcmp(argv[4], "include") == 0){
      flags |= RFS_PATH_INCLUDE;
    }
    else if (strcmp(argv[4], "exclude") == 0){
      flags |= RFS_PATH_EXCLUDE;
    }
    else{
      printf("\"include\" or \"exclude\" must be passed\n");
      usage();
      retval = 1;
      goto end;
    }

    if (strcmp(argv[5], "single") == 0){
      flags |= RFS_PATH_SINGLE;
    }
    else if (strcmp(argv[5], "subtree") == 0){
      flags |= RFS_PATH_SUBTREE;
    }
    else{
      printf("\"single\" or \"subtree\" must be passed\n");
      usage();
      retval = 1;
      goto end;
    }
    if (redirctl_filter_set_path(argv[2], argv[3], flags) != 0){
      retval = 3;
      goto end;
    }
  }
  else if (strcmp(argv[1], "activate") == 0){
    if (argc < 3){
      usage();
      retval = 1;
      goto end;
    }
    if (redirctl_activate_filter(argv[2]) != 0){
      retval = 3;
      goto end;
    }
  }
  else if (strcmp(argv[1], "deactivate") == 0){
    if (argc < 3){
      usage();
      retval = 1;
      goto end;
    }
    if (redirctl_deactivate_filter(argv[2]) != 0){
      retval = 3;
      goto end;
    }
  }
  else{
    usage();
    retval = 1;
  }

end:
  close(fd);
  return(retval);
}

