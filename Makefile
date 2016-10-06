CC=g++
CFLAGS=-Wall -shared -fPIC -ldl 
SOURCES=tcptrace.c lib.c
EXECUTABLE=tcptrace.so

all:
	$(CC) $(CFLAGS) $(SOURCES) -o $(EXECUTABLE)

clean:
	rm -f *.o
	rm $(EXECUTABLE)

run: all
	LD_PRELOAD=./$(EXECUTABLE) curl -s google.com > /dev/null
