all: binderAddInts server client

binderAddInts: binderAddInts.cpp
	g++ -o $@ -I../libs/include -L../libs $< -lpthread -lbinder -lrt

server: server.c
	gcc -o $@ -I../module/new $<

client: client.c
	gcc -o $@ -I../module/new $<

clean:
	rm -f binderAddInts server client
