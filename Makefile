CC=gcc
CFLAGS=-Wall -shared -fPIC -ljansson -ldl -lpthread -lpcap 
SOURCES=glibc_overrides.c lib.c tcp_spy.c strings.c tcp_json_builder.c packet_sniffer.c 
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

