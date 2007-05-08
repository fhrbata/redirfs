#include "urfs.h"

static void __user *useralloc(unsigned long size){
  return((void __user *) do_mmap(NULL, 0, size, VM_READ | VM_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0));
}

static void userfree(void __user *ptr, unsigned long size){
  do_munmap(current->mm, (unsigned long) ptr, size);
}

void __user *request_useralloc(struct request *request, unsigned long size){
  struct useralloc_chunk *chunk;

  if (size == 0){
    return(NULL);
  }

  chunk = kmalloc(sizeof(struct useralloc_chunk), GFP_ATOMIC);
  if (!chunk){
    return(NULL);
  }

  chunk->ptr = useralloc(size);
  if (!chunk->ptr){
    kfree(chunk);
    return(NULL);
  }
  chunk->size = size;
  dbgmsg(PRINTPREFIX "allocated addr 0x%08X size %lu\n", (int) chunk->ptr, chunk->size);

  INIT_LIST_HEAD(&chunk->list);
  spin_lock(&request->lock);
  list_add_tail(&chunk->list, &request->useralloc_chunks);
  spin_unlock(&request->lock);
  return(chunk->ptr);
}

void request_userfree(struct request *request, void __user *ptr){
  struct useralloc_chunk *chunk;
  struct useralloc_chunk *found = NULL;

  spin_lock(&request->lock); 
  list_for_each_entry(chunk, &request->useralloc_chunks, list){
    if (chunk->ptr == ptr){
      found = chunk;
      break;
    }
  }
  if (found){
    list_del(&found->list);
    userfree(found->ptr, found->size);
    kfree(found);
  }
  spin_unlock(&request->lock);
}

void request_userfreeall(struct request *request){
  struct useralloc_chunk *chunk;
  
  spin_lock(&request->lock); 
  while(!list_empty(&request->useralloc_chunks)){
    chunk = list_entry(request->useralloc_chunks.next, struct useralloc_chunk, list);
    list_del(request->useralloc_chunks.next);
    dbgmsg(PRINTPREFIX "freeing addr 0x%08X size %lu\n", (int) chunk->ptr, chunk->size);
    userfree(chunk->ptr, chunk->size);
    kfree(chunk);
  }
  spin_unlock(&request->lock);
}

struct request *request_create(unsigned long long request_id){
  struct request *request;

  request = (struct request *) kmalloc(sizeof(struct request), GFP_ATOMIC);
  if (!request){
    return(NULL);
  }

  init_completion(&request->completion);
  request->id = request_id;
  request->lock = SPIN_LOCK_UNLOCKED;
  spin_lock(&request->lock);
  INIT_LIST_HEAD(&request->useralloc_chunks);
  spin_unlock(&request->lock);
  return(request);
}

void request_destroy(struct request *request){  
  kfree(request);
}
