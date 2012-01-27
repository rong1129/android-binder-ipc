all: binder_tester binderAddInts server client

binder_tester: binder_tester.c
	gcc -Wall -o $@ -I../module $< 

binderAddInts: binderAddInts.cpp
	g++ -o $@ -I../libs/include -L../libs $< -lpthread -lbinder -lrt

server: server.c
	gcc -o $@ -I../module/new $<

client: client.c
	gcc -o $@ -I../module/new $<

clean:
	rm -f binder_tester binderAddInts server client
