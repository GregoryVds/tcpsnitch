CC=g++
CFLAGS=-Wall -shared -fPIC -ldl -ljansson
SOURCES=syscall_hooks.c lib.c tcp_spy.c strings.c logger.c
EXECUTABLE=netspy.so

all:
	$(CC) $(CFLAGS) $(SOURCES) -o $(EXECUTABLE)

clean:
	rm -f *.o
	rm $(EXECUTABLE)

run: all
	LD_PRELOAD=./$(EXECUTABLE) curl -s google.com > /dev/null
