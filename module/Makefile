ifneq ($(KERNELRELEASE),)
obj-m           := binder_old.o binder_new.o
binder_old-y	:= deps.o binder.o
binder_new-y	:= new/msg_queue.o new/binder.o

$(obj)/deps.o: $(src)/deps.h

$(obj)/deps.h: $(src)/gen_deps.sh
	$(src)/gen_deps.sh > $@
else
KDIR	?= /lib/modules/`uname -r`/build

all:
	$(MAKE) -C $(KDIR) V=0 M=$$PWD

clean:
	rm -rf deps.h new/*.o *.o *.ko *.mod.c *.symvers *.order .*.cmd .tmp_versions
endif
