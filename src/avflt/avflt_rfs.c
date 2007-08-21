#include "avflt.h"

#define AVFLT_REG_FOP_OPEN		0
#define AVFLT_REG_IOP_PERMISSION	1
#define AVFLT_REG_FOP_RELEASE		2

static int avflt_ctl(struct rfs_ctl *ctl);
static enum rfs_retv avflt_pre_open(rfs_context context,
		struct rfs_args *args);
static enum rfs_retv avflt_pre_permission(rfs_context context,
		struct rfs_args *args);

rfs_filter avflt;
static struct rfs_filter_info avflt_info = {"avflt", 666, 0, avflt_ctl};

int avflt_open = 1;
int avflt_close = 1;
int avflt_exec = 1;
spinlock_t avflt_rops_lock = SPIN_LOCK_UNLOCKED;

static struct rfs_op_info avflt_rops[] = {
	{RFS_REG_FOP_OPEN, NULL, NULL},
	{RFS_REG_IOP_PERMISSION, NULL, NULL},
	{RFS_OP_END, NULL, NULL}
};

static enum rfs_retv avflt_event(struct dentry *dentry, int event,
		struct rfs_args *args)
{
	struct avflt_check *check = NULL;
	int rv;

	if (avflt_pid_find(current->pid))
		return RFS_CONTINUE;

	rv = avflt_request_wait();

	if (rv < 0) {
		args->retv.rv_int = rv;
		return RFS_STOP;
	}

	if (rv == 1) {
		args->retv.rv_int = 0;
		return RFS_CONTINUE;
	}

	check = avflt_check_alloc();
	if (IS_ERR(check)) {
		avflt_request_put();
		args->retv.rv_int = rv;
		return RFS_STOP;
	}

	rv = rfs_get_filename(dentry, check->fn, check->fn_size);
	if (rv) {
		args->retv.rv_int = rv;
		avflt_request_put();
		avflt_check_put(check);
		return RFS_STOP;
	}

	check->event = event;
	check->fn_len = strlen(check->fn);

	rv = avflt_request_queue(check);
	if (rv) {
		args->retv.rv_int = 0;
		avflt_request_put();
		avflt_check_put(check);
		return RFS_STOP;
	}

	rv = avflt_reply_wait(check);
	if (rv) {
		args->retv.rv_int = rv;
		avflt_check_put(check);
		return RFS_STOP;
	}

	if (atomic_read(&check->deny)) {
		avflt_check_put(check);
		args->retv.rv_int = -EPERM;
		return RFS_STOP;
	}

	avflt_check_put(check);
	args->retv.rv_int = 0;

	return RFS_CONTINUE;
}

static enum rfs_retv avflt_pre_open(rfs_context context, struct rfs_args *args)
{
	struct dentry *dentry = args->args.f_open.file->f_dentry;
	
	return avflt_event(dentry, AV_EVENT_OPEN, args);
}

static enum rfs_retv avflt_pre_release(rfs_context context, struct rfs_args *args)
{
	struct dentry *dentry = args->args.f_release.file->f_dentry;
	
	return avflt_event(dentry, AV_EVENT_CLOSE, args);
}


static enum rfs_retv avflt_pre_permission(rfs_context context,
		struct rfs_args *args)
{
	struct dentry *dentry;

	if (!args->args.i_permission.nd)
		return RFS_CONTINUE;

	if (!(args->args.i_permission.mask & MAY_EXEC))
		return RFS_CONTINUE;

	dentry = args->args.i_permission.nd->dentry;

	return avflt_event(dentry, AV_EVENT_EXEC, args);
}

static int avflt_ctl(struct rfs_ctl *ctl)
{
	int err = 0;

	switch (ctl->id) {
		case RFS_CTL_ACTIVATE:
			err = rfs_activate_filter(avflt);
			break;

		case RFS_CTL_DEACTIVATE:
			err = rfs_deactivate_filter(avflt);
			break;

		case RFS_CTL_SETPATH:
			err = rfs_set_path(avflt, &ctl->data.path_info); 
			break;
	}

	return err;
}

int avflt_rfs_set_ops(void)
{
	if (avflt_open) 
		avflt_rops[AVFLT_REG_FOP_OPEN].pre_cb = avflt_pre_open;
	else
		avflt_rops[AVFLT_REG_FOP_OPEN].pre_cb = NULL;

	if (avflt_exec) 
		avflt_rops[AVFLT_REG_IOP_PERMISSION].pre_cb = avflt_pre_permission;
	else
		avflt_rops[AVFLT_REG_IOP_PERMISSION].pre_cb = NULL;

	if (avflt_close) 
		avflt_rops[AVFLT_REG_FOP_RELEASE].pre_cb = avflt_pre_release;
	else
		avflt_rops[AVFLT_REG_FOP_RELEASE].pre_cb = NULL;

	return rfs_set_operations(avflt, avflt_rops);
}

int avflt_rfs_init(void)
{
	int err;

	err = rfs_register_filter(&avflt, &avflt_info);
	if (err)
		return err;

	spin_lock(&avflt_rops_lock);
	err = avflt_rfs_set_ops();
	spin_unlock(&avflt_rops_lock);
	if (err)
		goto error;

	err = rfs_activate_filter(avflt);
	if (err)
		goto error;

	return 0;

error:
	rfs_unregister_filter(avflt);
	return err;
}

void avflt_rfs_exit(void)
{
	int err;

	err = rfs_unregister_filter(avflt);
	if (err)
		printk(KERN_ERR "avflt: rfs_unregister_filter failed(%d)\n", err);
}


