CC=gcc
CFLAGS=-Wall -shared -fPIC -ldl -lpthread -lpcap 
SOURCES=syscall_hooks.c lib.c tcp_spy.c strings.c tcp_json_builder.c packet_sniffer.c /usr/local/lib/libjansson.a
EXECUTABLE=netspy.so
ENV=NETSPY_PATH=~/host LD_PRELOAD=./$(EXECUTABLE) 

all:
	$(CC) $(SOURCES) $(CFLAGS) -o $(EXECUTABLE)

clean:
	rm -f *.o
	rm $(EXECUTABLE)

curl: all
	$(ENV) curl -s google.com > /dev/null

angular: all
	$(ENV) curl -s https://ajax.googleapis.com/ajax/libs/angularjs/1.5.7/angular.min.js > /dev/null

valgrind: all
	$(ENV) valgrind --leak-check=yes gdb curl -s google.com > /dev/null

