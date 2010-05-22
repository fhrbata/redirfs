#include <sys/types.h>
#include <sys/module.h>
#include <sys/systm.h>  /* uprintf */
#include <sys/sbuf.h>  /* sbuf_print */
#include <sys/errno.h>
#include <sys/param.h>  /* defines used in kernel.h */
#include <sys/kernel.h> /* types used in module initialization */
#include <sys/conf.h>   /* cdevsw struct */
#include <sys/uio.h>    /* uio struct */
#include <sys/malloc.h>
#include <sys/malloc.h>
#include <fs/larefs/lrfs.h>
#include <dev/larefsdev/larefsdev.h>

/* Function prototypes */
static d_open_t      lrfs_open;
static d_close_t     lrfs_close;
static d_read_t      lrfs_read;

/* Character device entry points */
static struct cdevsw lrfs_cdevsw = {
	.d_version = D_VERSION,
	.d_open = lrfs_open,
	.d_close = lrfs_close,
	.d_read = lrfs_read,
	.d_name = "lrfs",
};

/* vars */
static struct cdev *lrfs_dev;
static struct sbuf *lrfs_msgbuf;

MALLOC_DECLARE(M_LRFSBUF);
MALLOC_DEFINE(M_LRFSBUF, "lrfsbuffer", "buffer for lrfs module");

/*
 * This function is called by the kld[un]load(2) system calls to
 * determine what actions to take when a module is loaded or unloaded.
 */

static int
event_handler(struct module *m, int event, void *arg)
{
	int err = 0;

	switch (event) {

	case MOD_LOAD:
		lrfs_dev = make_dev(&lrfs_cdevsw,
			0,
			UID_ROOT,
			GID_WHEEL,
			0600,
			"lrfs");
		break;

	case MOD_UNLOAD:
		destroy_dev(lrfs_dev);
		break;

	default:
		err = EOPNOTSUPP;
	break;
	}
	return(err);
}

static int
read_flt_tobuf(struct larefs_filter_t *filter,
	struct sbuf *sbf, struct thread *td) 
{
	struct lrfs_filter_info *finfo;
	char *rbuf, *fbuf, *tbuf = "?Unknown?";
	int err;

	sbuf_printf(sbf, "Filter: %s\nUsed: %d\nRegistered operations: ",
		 filter->name, filter->usecount);

	for (int i = 0; (filter->reg_ops[i].op_id != LAREFS_BOTTOM); i++) {
		sbuf_printf(sbf, "%s, ",filter_op_names[filter->reg_ops[i].op_id]);
	}
	sbuf_printf(sbf, "\n");

	SLIST_FOREACH(finfo, &filter->used, entry) {

		/* 
		 * Get the pathname. This may possibly cause some problems
		 * since vn_fullpath is not very reliable. 
		 */
		if (finfo->avn) {
			err = vn_fullpath(td, finfo->avn, &rbuf, &fbuf);
			if (err) {
				rbuf = tbuf;;
			}
		} else
			rbuf = tbuf;;

		sbuf_printf(sbf, "Path: %s\nPriority: %d\nActive: %d\n",
			 rbuf, finfo->priority, finfo->active);

		free(fbuf, M_TEMP);
	}

	return (0);
}

static int
lrfs_open(struct cdev *dev, int oflags, int devtype, struct thread *p)
{
	int err = 0;
	struct larefs_filter_t *filter = NULL;

	lrfs_msgbuf = sbuf_new_auto();	
	
	mtx_lock(&registered_filters->regmtx);

	SLIST_FOREACH(filter, &registered_filters->head, entry) {
		mtx_lock(&filter->fltmtx);
		read_flt_tobuf(filter, lrfs_msgbuf, p);
		mtx_unlock(&filter->fltmtx);
	}
	mtx_unlock(&registered_filters->regmtx);

	sbuf_finish(lrfs_msgbuf);
	return(err);
}

static int
lrfs_close(struct cdev *dev, int fflag, int devtype, struct thread *p)
{
	sbuf_delete(lrfs_msgbuf);
	return(0);
}

static int
lrfs_read(struct cdev *dev, struct uio *uio, int ioflag)
{
	int err = 0;
	int amt;
	int len;

	len = lrfs_msgbuf->s_len;
	amt = MIN(len, (len - uio->uio_offset > 0) ?
		len - uio->uio_offset : 0);
	if ((err = uiomove(lrfs_msgbuf->s_buf, amt, uio)) != 0) {
		uprintf("uiomove failed!\n");
	}

	return err;
}

DEV_MODULE(larefsdev,event_handler,NULL);
MODULE_DEPEND(larefsdev, larefs, 1, 1, 1);

