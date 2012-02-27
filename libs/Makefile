all: libbinder.a

include cutils/Makefile
include utils/Makefile
include binder/Makefile

CFLAGS := -I.. -Iinclude -DHAVE_PTHREADS -DHAVE_SYS_UIO_H -DHAVE_ENDIAN_H #-DINLINE_TRANSACTION_DATA

libbinder.a: $(objects)
	ar cr $@ $^

clean:
	rm -f  libbinder.a `find -name \*.o`

%.o : %.cpp
	gcc $(CFLAGS) -c -o $@ $<
%.o : %.c
	gcc $(CFLAGS) -c -o $@ $<
