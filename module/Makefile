ifneq ($(KERNELRELEASE),)
obj-m           := binder_x86.o
binder_x86-y	:= deps.o binder.o

else

KDIR		?= /lib/modules/`uname -r`/build

all: deps.h
	$(MAKE) -C $(KDIR) V=0 M=$$PWD

deps.h: gen_deps.sh
	./gen_deps.sh
	
clean:
	rm -f deps.h *.o *.ko *.mod.c *.symvers *.order

endif
