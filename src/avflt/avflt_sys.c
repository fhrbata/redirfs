#include "avflt.h"

#define avflt_attr(__name, __mode)			\
struct attribute avflt_attr_##__name = { 		\
	.name  = __stringify(__name), 			\
	.mode  = __mode, 				\
	.owner = THIS_MODULE				\
}

extern spinlock_t avflt_rops_lock;
extern int avflt_open;
extern int avflt_exec;
extern int avflt_close;
extern int avflt_close_modified;

extern int avflt_request_nr;
extern int avflt_reply_nr;
extern int avflt_request_max;
extern int avflt_reply_max;
extern spinlock_t avflt_request_lock;
extern spinlock_t avflt_reply_lock;

static struct kobject avflt_events;
static struct kobject avflt_queues;
static struct kobj_type avflt_events_ktype;
static struct kobj_type avflt_queues_ktype;
static struct sysfs_ops avflt_events_ops;
static struct sysfs_ops avflt_queues_ops;

static avflt_attr(open, 0644);
static avflt_attr(exec, 0644);
static avflt_attr(close, 0644);
static avflt_attr(close_modified, 0644);

static avflt_attr(request, 0444);
static avflt_attr(reply, 0444);
static avflt_attr(request_max, 0644);
static avflt_attr(reply_max, 0644);

static struct attribute *avflt_events_attrs[] = {
	&avflt_attr_open,
	&avflt_attr_exec,
	&avflt_attr_close,
	&avflt_attr_close_modified,
	NULL
};

static struct attribute *avflt_queues_attrs[] = {
	&avflt_attr_request,
	&avflt_attr_reply,
	&avflt_attr_request_max,
	&avflt_attr_reply_max,
	NULL
};

static ssize_t avflt_events_show(struct kobject *kobj, struct attribute *attr,
		char *buf)
{
	int *event;
	int val;


	if (!strcmp(attr->name, "open"))
		event = &avflt_open;

	else if (!strcmp(attr->name, "close"))
		event = &avflt_close;

	else if (!strcmp(attr->name, "exec"))
		event = &avflt_exec;

	else if (!strcmp(attr->name, "close_modified"))
		event = &avflt_close_modified;

	else 
		return -EINVAL;

	spin_lock(&avflt_rops_lock);
	val = *event;
	spin_unlock(&avflt_rops_lock);

	return snprintf(buf, PAGE_SIZE, "%d", val);
}

static ssize_t avflt_events_store(struct kobject *kobj, struct attribute *attr,
		const char *buf, size_t size)
{
	int *event;
	int val;
	int rv;

	if (sscanf(buf, "%d", &val) != 1)
		return -EINVAL;

	if (val < 0 || val > 1)
		return -EINVAL;


	if (!strcmp(attr->name, "open"))
		event = &avflt_open;

	else if (!strcmp(attr->name, "close"))
		event = &avflt_close;

	else if (!strcmp(attr->name, "exec"))
		event = &avflt_exec;

	else if (!strcmp(attr->name, "close_modified"))
		event = &avflt_close_modified;

	else
		return -EINVAL;

	spin_lock(&avflt_rops_lock);

	if (val == *event) {
		spin_unlock(&avflt_rops_lock);
		return size;
	}

	*event = val;

	if ((rv = avflt_rfs_set_ops())) {
		spin_unlock(&avflt_rops_lock);
		return rv;
	}

	spin_unlock(&avflt_rops_lock);

	return size;
}

static ssize_t avflt_queues_show(struct kobject *kobj, struct attribute *attr,
		char *buf)
{
	int val;

	if (!strcmp(attr->name, "request")) {
		spin_lock(&avflt_request_lock);
		val = avflt_request_nr;
		spin_unlock(&avflt_request_lock);

	} else if (!strcmp(attr->name, "reply")) {
		spin_lock(&avflt_reply_lock);
		val = avflt_reply_nr;
		spin_unlock(&avflt_reply_lock);

	} else if (!strcmp(attr->name, "request_max")) {
		spin_lock(&avflt_request_lock);
		val = avflt_request_max;
		spin_unlock(&avflt_request_lock);

	} else if (!strcmp(attr->name, "reply_max")) {
		spin_lock(&avflt_reply_lock);
		val = avflt_reply_max;
		spin_unlock(&avflt_reply_lock);

	} else
		return -EINVAL;

	return snprintf(buf, PAGE_SIZE, "%d", val);
}

static ssize_t avflt_queues_store(struct kobject *kobj, struct attribute *attr,
		const char *buf, size_t size)
{
	int val;
	if (sscanf(buf, "%d", &val) != 1)
		return -EINVAL;
	
	if (val < 0)
		return -EINVAL;

	if (!strcmp(attr->name, "request_max")) {
		spin_lock(&avflt_request_lock);
		avflt_request_max = val;
		spin_unlock(&avflt_request_lock);

	} else if (!strcmp(attr->name, "reply_max")) {
		spin_lock(&avflt_reply_lock);
		avflt_reply_max = val;
		spin_unlock(&avflt_reply_lock);

	} else
		return -EINVAL;

	return size;
}

int avflt_sys_init(struct kobject *parent)
{
	int rv = 0;

	memset(&avflt_events, 0, sizeof(struct kobject));
	memset(&avflt_queues, 0, sizeof(struct kobject));
	memset(&avflt_events_ktype, 0, sizeof(struct kobj_type));
	memset(&avflt_queues_ktype, 0, sizeof(struct kobj_type));
	memset(&avflt_events_ops, 0, sizeof(struct sysfs_ops));
	memset(&avflt_queues_ops, 0, sizeof(struct sysfs_ops));

	avflt_events_ops.show = avflt_events_show;
	avflt_events_ops.store = avflt_events_store;

	avflt_queues_ops.show = avflt_queues_show;
	avflt_queues_ops.store = avflt_queues_store;

	avflt_events_ktype.release = NULL;
	avflt_events_ktype.default_attrs = avflt_events_attrs;
	avflt_events_ktype.sysfs_ops = &avflt_events_ops;

	avflt_queues_ktype.release = NULL;
	avflt_queues_ktype.default_attrs = avflt_queues_attrs;
	avflt_queues_ktype.sysfs_ops = &avflt_queues_ops;

	kobject_set_name(&avflt_events, "%s", "events");
	avflt_events.parent = parent;
	avflt_events.ktype = &avflt_events_ktype;

	kobject_set_name(&avflt_queues, "%s", "queues");
	avflt_queues.parent = parent;
	avflt_queues.ktype = &avflt_queues_ktype;

	if ((rv = kobject_register(&avflt_events)))
		return rv;

	if ((rv = kobject_register(&avflt_queues))) {
		kobject_unregister(&avflt_events);
		return rv;
	}

	return 0;
}

void avflt_sys_exit(void)
{
	kobject_unregister(&avflt_events);
	kobject_unregister(&avflt_queues);
}

