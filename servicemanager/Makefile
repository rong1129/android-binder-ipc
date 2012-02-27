all: servicemanager

#CFLAGS := -DINLINE_TRANSACTION_DATA 

servicemanager: binder.o service_manager.o
	gcc -o $@ $^

clean:
	rm -f *.o servicemanager
	
%.o: %.c
	gcc -I.. $(CFLAGS) -c -o $@ $<
