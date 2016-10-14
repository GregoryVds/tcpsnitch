CC=g++
CFLAGS=-Wall -shared -fPIC -ldl 
SOURCES=syscall_hooks.c lib.c tcp_spy.c strings.c tcp_json_builder.c /usr/local/lib/libjansson.a
EXECUTABLE=netspy.so

all:
	$(CC) $(CFLAGS) $(SOURCES) -o $(EXECUTABLE)

clean:
	rm -f *.o
	rm $(EXECUTABLE)

run: all
	NETSPY_PATH=~/host/dump.json LD_PRELOAD=./$(EXECUTABLE) curl -s google.com > /dev/null
