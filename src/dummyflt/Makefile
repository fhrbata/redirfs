obj-m += dummyflt.o

#we need version info from redirfs module
$(obj)/dummyflt.o: $(obj)/.tmp_versions/redirfs.mod

$(obj)/.tmp_versions/redirfs.mod: $(PWD)/../redirfs/redirfs.ko
        @@ cd $(PWD); \
        rm -f $(obj)/.tmp_versions/redirfs.mod; \
        ln -s ../../redirfs/.tmp_versions/redirfs.mod $(obj)/.tmp_versions/

