#include <linux/module.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/sysfs.h>
#include <asm/uaccess.h>
#include "buffer.h"
#include "../headers/sysfs_test.h"

#define PRINTPREFIX "sysfs_test: "
#define DATAPAGESMAX GETNUMOFPAGES(LOCBUFLEN, PAGE_SIZE)

struct datapage{
  struct attribute attr;
  char name[32];
  int pagenumber;
};

static struct datapage _datapages[DATAPAGESMAX];

#define test_attr(_name) \
static struct subsys_attribute _name##_attr = { \
  .attr = { \
    .name = __stringify(_name), \
    .mode = 0644, \
  }, \
  .show = _name##_show, \
  .store = _name##_store, \
}

static struct kobject datapages;

static int change_locbuf_currlen(unsigned int new_size){
  int oldnumpages;
  int newnumpages;
  int i;
  struct datapage *pdatapage;

  if (new_size > LOCBUFLEN){
    return(-1);
  }
  if (new_size != locbuf_currlen){
    oldnumpages = GETNUMOFPAGES(locbuf_currlen, PAGE_SIZE);
    newnumpages = GETNUMOFPAGES(new_size, PAGE_SIZE);
    if (oldnumpages < newnumpages){
      for(i = oldnumpages; i < newnumpages; i++){
        pdatapage = &_datapages[i];
	pdatapage->pagenumber = i;
	sprintf(pdatapage->name, "%d", i);
	pdatapage->attr.name = pdatapage->name;
        pdatapage->attr.owner = THIS_MODULE;
        pdatapage->attr.mode = 0644;
	sysfs_create_file(&datapages, &pdatapage->attr); 
      }
    }
    if (oldnumpages > newnumpages){
      for(i = oldnumpages - 1; i >= newnumpages; i--){
	sysfs_remove_file(&datapages, &_datapages[i].attr); 
      } 
    }
    locbuf_currlen = new_size;
  }
  return(0);
}

ssize_t datapages_show(struct kobject *kobject, struct attribute *attribute, char *page){
  struct datapage *pdatapage = (struct datapage *) attribute;
  unsigned int start = pdatapage->pagenumber * PAGE_SIZE;  
  unsigned int len = locbuf_currlen - start;
  
  if (len > PAGE_SIZE){
    len = PAGE_SIZE;
  }
  
  // printk(PRINTPREFIX "show: start: %u, len: %u\n", start, len);
  memcpy(page, locbuf + start, len);
  return(len);
}
ssize_t datapages_store(struct kobject *kobject, struct attribute *attribute, const char *page, size_t size){
  struct datapage *pdatapage = (struct datapage *) attribute;
  unsigned int start = pdatapage->pagenumber * PAGE_SIZE;  
  unsigned int len = locbuf_currlen - start;
  
  if (len > PAGE_SIZE){
    len = PAGE_SIZE;
  }

  // printk(PRINTPREFIX "store: start: %u, len: %u\n", start, len);  
  memcpy(locbuf + start, page, len);
  return(len);
}

static struct sysfs_ops datapages_ops = {
  .show = datapages_show,
  .store = datapages_store,
};

static ssize_t datasize_show(struct subsystem *subsys, char *page){
  int len;
  
  len = sprintf(page, "%u\n", locbuf_currlen);
  return(len);
}

static ssize_t datasize_store(struct subsystem *subsys, const char *page, size_t size){
  unsigned int len;

  if (sscanf(page, "%u", &len) == 1){
    if (change_locbuf_currlen(len) == 0){
      return(size);
    }
  }
  return(-EINVAL);  
}

test_attr(datasize);

static ssize_t pagesize_show(struct subsystem *subsys, char *page){
  int len;
  
  len = sprintf(page, "%ld\n", PAGE_SIZE);
  return(len);
}

static ssize_t pagesize_store(struct subsystem *subsys, const char *page, size_t size){
  return(size);
}

test_attr(pagesize);

static struct attribute *g[] = {
  &datasize_attr.attr,
  &pagesize_attr.attr,
  NULL,
};
		
static struct attribute_group attr_group = {
  .attrs = g,
};
			
static struct kobj_type sysfs_test_datapages_ktype = {
  .release = NULL,
  .sysfs_ops = &datapages_ops,
  .default_attrs = NULL,
};

decl_subsys(sysfs_test, NULL, NULL);

static int __init _init_module(void){
  int error;  

  if (!alloc_locbuf()){
    printk(PRINTPREFIX "cannot allocate local buffer\n");
    return(-1);
  }	  
  error = subsystem_register(&sysfs_test_subsys);
  if (!error){
     error = sysfs_create_group(&sysfs_test_subsys.kset.kobj, &attr_group);
  }
  else{
    printk(PRINTPREFIX "cannot register sysfs sybsystem\n");
    free_locbuf();
    return(-1);
  }

  // zero allocated memory
  memset(&datapages, 0, sizeof (struct kobject));
  // set kset, ktype and parent object
  datapages.kset = NULL;
  datapages.ktype = &sysfs_test_datapages_ktype;
  datapages.parent = &sysfs_test_subsys.kset.kobj;
  // must set name of the object
  kobject_set_name(&datapages, "datapages");
  // init and add kobject in one function
  kobject_register(&datapages);
  
  locbuf_currlen = 0;
  
  printk(PRINTPREFIX "sysfs test initialized\n");
  return(0);
}

static void __exit _cleanup_module(void){
  free_locbuf();
  kobject_unregister(&datapages);
  subsystem_unregister(&sysfs_test_subsys);
}

module_init(_init_module);
module_exit(_cleanup_module);

MODULE_LICENSE("GPL");
