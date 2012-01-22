ifneq ($(KERNELRELEASE),)
#obj-m           := binder_old.o
obj-m           := binder_new.o
binder_old-y	:= deps.o binder.o
binder_new-y	:= new/msg_queue.o new/binder.o

else

KDIR		?= /lib/modules/`uname -r`/build

all:
	$(MAKE) -C $(KDIR) V=0 M=$$PWD

deps.o: deps.h deps.c
deps.h: gen_deps.sh
	./gen_deps.sh
	
clean:
	rm -rf deps.h new/*.o *.o *.ko *.mod.c *.symvers *.order .*.cmd .tmp_versions

endif
