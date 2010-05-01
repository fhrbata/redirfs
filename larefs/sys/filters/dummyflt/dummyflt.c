#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/vnode.h>

#include <fs/larefs/larefs.h>

int pre_dummyflt_open(struct vop_generic_args *ap);
int post_dummyflt_open(struct vop_generic_args *ap);
int pre_dummyflt_lookup(struct vop_generic_args *ap);
int post_dummyflt_lookup(struct vop_generic_args *ap);

struct larefs_vop_vector dummyflt_vnodeops[] = {
	{LAREFS_OPEN, pre_dummyflt_open, post_dummyflt_open},
	{LAREFS_LOOKUP, pre_dummyflt_lookup, post_dummyflt_open},
	{LAREFS_BOTTOM, NULL, NULL}
};

static struct larefs_filter_t filter_conf = {
	"Dummyflt",
	dummyflt_vnodeops	
};

int
pre_dummyflt_open(struct vop_generic_args *ap)
{
	uprintf("%s : %s\n", filter_conf.name, __func__);
	return (0);
}

int
post_dummyflt_open(struct vop_generic_args *ap)
{
	uprintf("%s : %s\n", filter_conf.name, __func__);
	return (0);
}

int
pre_dummyflt_lookup(struct vop_generic_args *ap)
{
	uprintf("%s : %s\n", filter_conf.name, __func__);
	return (0);
}

int
post_dummyflt_lookup(struct vop_generic_args *ap)
{
	uprintf("%s : %s\n", filter_conf.name, __func__);
	return (0);
}


static int event_handler(struct module *module, int event, void *arg) {
        int err = 0;
        switch (event) {
        case MOD_LOAD:
                uprintf("Hello dummyflt is here! \n");
		err = larefs_register_filter(&filter_conf);
		uprintf("filter registration : %d\n",err);
                break;
        case MOD_UNLOAD:
                uprintf("Dummyflt is leaving\n");
		err = larefs_unregister_filter(&filter_conf);
                break;
        default:
                err = EOPNOTSUPP;
                break;
        }
       
        return(err);
}

static moduledata_t dummyflt_conf = {
    "hello_fsm",
     event_handler,
     NULL
};

DECLARE_MODULE(dummyflt, dummyflt_conf, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
MODULE_DEPEND(dummyflt, larefs, 1, 1, 1);
