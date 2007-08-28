#include "avflt.h"

extern int avflt_request_nr;
extern spinlock_t avflt_request_lock;
extern wait_queue_head_t avflt_request_waitq;
static struct class *avflt_class;
static struct class_device *avflt_class_device;
static dev_t avflt_dev;

static int avflt_dev_open(struct inode *inode, struct file *file)
{
	int rv;

	rv = avflt_pid_add(current->tgid);
	if (rv)
		return rv;

	return 0;
}

static int avflt_dev_release(struct inode *inode, struct file *file)
{
	avflt_pid_rem(current->tgid);

	return 0;
}

static ssize_t avflt_dev_read(struct file *file, char __user *buf,
		size_t size, loff_t *pos)
{
	struct avflt_check *check = NULL;
	struct avflt_ucheck ucheck;
	int rv;

	if (!buf)
		return -EINVAL;

	if (size != sizeof(struct avflt_ucheck))
		return -EINVAL;

	if (copy_from_user(&ucheck, buf, size))
		return -EFAULT;

	if (ucheck.mag != AV_CTL_MAGIC)
		return -EINVAL;

	if (ucheck.ver != AV_CTL_VERSION)
		return -EINVAL;

	if (!ucheck.fn)
		return -EINVAL;

	while (!check) {
		rv = avflt_request_available_wait();
		if (rv)
			return rv;

		check = avflt_request_dequeue();
	}

	if (ucheck.fn_size < check->fn_len) {
		if (avflt_request_queue(check)) 
			avflt_check_done(check);

		avflt_check_put(check);

		return -ENAMETOOLONG;
	}

	rv = avflt_reply_queue(check);
	if (rv == 1) {
		avflt_check_done(check);
		avflt_check_put(check);
	}

	if (rv < 0) {
		if (avflt_request_queue(check)) 
			avflt_check_done(check);

		avflt_check_put(check);
		return rv;
	}

	ucheck.event = check->event;
	ucheck.id = check->id;

	if (copy_to_user(ucheck.fn, check->fn, check->fn_len)) {
		BUG_ON(!avflt_reply_dequeue(check->id));
		if (avflt_request_queue(check)) 
			avflt_check_done(check);

		avflt_check_put(check);

		return -EFAULT;
	}

	if (copy_to_user(buf, &ucheck, size)) {
		BUG_ON(!avflt_reply_dequeue(check->id));
		if (avflt_request_queue(check))
			avflt_check_done(check);

		avflt_check_put(check);

		return -EFAULT;
	}

	avflt_request_put();

	return size;
}

static ssize_t avflt_dev_write(struct file *file, const char __user *buf,
		size_t size, loff_t *pos)
{
	struct avflt_check *check = NULL;
	struct avflt_ucheck ucheck;

	if (!buf)
		return -EINVAL;

	if (size != sizeof(struct avflt_ucheck))
		return -EINVAL;

	if (copy_from_user(&ucheck, buf, size))
		return -EFAULT;

	if (ucheck.mag != AV_CTL_MAGIC)
		return -EINVAL;

	if (ucheck.ver != AV_CTL_VERSION)
		return -EINVAL;

	check = avflt_reply_dequeue(ucheck.id);
	if (!check) {
		BUG();
		printk(KERN_ERR "avflt: reply(%d) not found\n", ucheck.id);
		return -ENOENT;
	}

	atomic_set(&check->deny, ucheck.deny);
	avflt_check_done(check);
	avflt_check_put(check);

	return size;
}

static unsigned int avflt_dev_poll(struct file *file, struct poll_table_struct *pt)
{
	unsigned int mask = 0;
	poll_wait(file, &avflt_request_waitq, pt);

	spin_lock(&avflt_request_lock);
	if (avflt_request_nr)
		mask |= POLLIN | POLLRDNORM;
	spin_unlock(&avflt_request_lock);

	mask |= POLLOUT | POLLWRNORM;

	return mask;
}

static struct file_operations avflt_fops = {
	.owner = THIS_MODULE,
	.open = avflt_dev_open,
	.release = avflt_dev_release,
	.read = avflt_dev_read,
	.write = avflt_dev_write,
	.poll = avflt_dev_poll,
};

int avflt_dev_init(void)
{
	int major;

	major = register_chrdev(0, "avflt", &avflt_fops);
	if (major < 0)
		return major;

	avflt_dev = MKDEV(major, 0);

	avflt_class = class_create(THIS_MODULE, "avflt");
	if (IS_ERR(avflt_class)) {
		unregister_chrdev(major, "avflt");
		return PTR_ERR(avflt_class);
	}

	avflt_class_device = class_device_create(avflt_class, NULL, avflt_dev, NULL, "avflt");
	if (IS_ERR(avflt_class_device)) {
		class_destroy(avflt_class);
		unregister_chrdev(major, "avflt");
		return PTR_ERR(avflt_class_device);
	}

	return 0;
}

void avflt_dev_exit(void)
{
	int err;

	class_device_destroy(avflt_class, avflt_dev);
	class_destroy(avflt_class);
	err = unregister_chrdev(MAJOR(avflt_dev), "avflt");
	if (err)
		printk(KERN_ERR "avflt: unregister_chrdev failed(%d)\n", err);
}
