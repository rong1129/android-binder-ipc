all: binderAddInts

binderAddInts: binderAddInts.cpp
	g++ -o $@ -I../libs/include -L../libs $< -lpthread -lbinder -lrt
clean:
	rm -f binderAddInts
