#include <asm/uaccess.h>
#include "urfs.h"

int conn_alloc_ufilter(struct conn *c, int *ufilter_id){
  struct ufilter *ufilter;
  int i;
  int retval = 0;

  spin_lock(&c->lock);
  for(i = 0; i < MAX_UFILTERS_PER_CONN ;i++){
    if (c->ufilter[i] == NULL){
      break;
    }
  }

  if (i == MAX_UFILTERS_PER_CONN){
    retval = -1;
    goto end;
  }

  ufilter = (struct ufilter *) kmalloc(sizeof(struct ufilter), GFP_KERNEL);
  if (!ufilter){
    retval = -2;
    goto end;
  }
  *ufilter_id = i;
  ufilter->id = i;
  ufilter->c = c;
  c->ufilter[i] = ufilter;
end:
  spin_unlock(&c->lock);
  return(retval);
}

static void free_ufilter(struct conn *c, int ufilter_id){
  if (ufilter_id < 0 || ufilter_id >= MAX_UFILTERS_PER_CONN){
    return;
  }
  if (c->ufilter[ufilter_id]){
    kfree(c->ufilter[ufilter_id]);
    c->ufilter[ufilter_id] = NULL;
  }
}

void conn_free_ufilter(struct conn *c, int ufilter_id){
  spin_lock(&c->lock);
  free_ufilter(c, ufilter_id);
  spin_unlock(&c->lock);
}

static void cleanup_ufilters(struct conn *c){
  int i;
  struct ufilter *ufilter;
  
  for(i = 0; i < MAX_UFILTERS_PER_CONN; i++){
    ufilter = c->ufilter[i];
    if (ufilter){
      ufilter_unregister(c->ufilter[i]);
    }
    free_ufilter(c, i);
  }
}

struct ufilter *conn_get_ufilter(struct conn *c, int ufilter_id){
  struct ufilter *ufilter = NULL;
  
  spin_lock(&c->lock);
  if (ufilter_id < 0 || ufilter_id >= MAX_UFILTERS_PER_CONN){
    goto end;
  }
  ufilter = c->ufilter[ufilter_id]; 

end:
  spin_unlock(&c->lock);
  return(ufilter);
}

static void init_ufilters(struct conn *c){
  int i;
  
  for(i = 0; i < MAX_UFILTERS_PER_CONN; i++){
    c->ufilter[i] = NULL;
  }
}

struct conn *conn_create(void){
  struct conn *c;

  c = (struct conn *) kmalloc(sizeof(struct conn), GFP_KERNEL);
  if (c){
    c->lock = SPIN_LOCK_UNLOCKED;
    atomic_set(&c->callbacks_enabled, 0);
    spin_lock(&c->lock);
    init_ufilters(c);
    INIT_LIST_HEAD(&c->msgs_to_send);
    init_waitqueue_head(&c->waitq);
    spin_unlock(&c->lock);
  }
  return(c);
}

void conn_destroy(struct conn *c){
  spinlock_t lock;

  spin_lock(&c->lock);
  cleanup_ufilters(c);
  memcpy(&lock, &c->lock, sizeof(spinlock_t));
  kfree(c);
  spin_unlock(&lock);
}

void conn_msg_append(struct conn *c, struct omsg_list *omsg_list){
  INIT_LIST_HEAD(&omsg_list->list);
  spin_lock(&c->lock); 
  list_add_tail(&omsg_list->list, &c->msgs_to_send);
  dbgmsg(PRINTPREFIX "waking up queue\n");
  wake_up(&c->waitq);
  spin_unlock(&c->lock);
}

void conn_msg_insert(struct conn *c, struct omsg_list *omsg_list){
  INIT_LIST_HEAD(&omsg_list->list);
  spin_lock(&c->lock); 
  list_add(&omsg_list->list, &c->msgs_to_send);
  dbgmsg(PRINTPREFIX "waking up queue\n");
  wake_up(&c->waitq);
  spin_unlock(&c->lock);
}

int conn_msg_pending(struct conn *c){
  int retval;

  spin_lock(&c->lock);
  retval = !list_empty(&c->msgs_to_send);
  spin_unlock(&c->lock);
  return(retval);
}

struct omsg_list *conn_msg_get_next(struct conn *c){
  struct omsg_list *omsg_list = NULL;

  spin_lock(&c->lock);
  if (!list_empty(&c->msgs_to_send)){
    omsg_list = list_entry(c->msgs_to_send.next, struct omsg_list, list);
    list_del(c->msgs_to_send.next);
  }
  spin_unlock(&c->lock);
  return(omsg_list);
}

void conn_switch_callbacks(struct conn *c, int enable){
  atomic_set(&c->callbacks_enabled, enable);
}

int conn_enabled_callbacks(struct conn *c){
  return(atomic_read(&c->callbacks_enabled));
}
