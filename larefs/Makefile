SUBDIR=	sys/modules/larefs \
	sys/modules/dummyflt \
	sys/modules/larefsdev \
	sbin/larefs

# Should be built from sources tree
# SUBDIR+= lib/libpam/modules/pam_pefs

load:
	kldload sys/modules/larefs/larefs.ko
	kldload sys/modules/dummyflt/dummyflt.ko
	kldload sys/modules/larefsdev/larefsdev.ko

unload:
	kldunload dummyflt
	kldunload larefsdev
	kldunload larefs

mount:
	mount -t larefs ./sys ./test
	mount -t larefs ./sbin ./test1

umount:
	umount ./test
	umount ./test1

start:
	make 
	make load
	make mount

stop:
	make umount
	make unload

	

.include <bsd.subdir.mk>
