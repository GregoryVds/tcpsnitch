CC=gcc
CFLAGS=-ggdb -Wall -shared -fPIC -ljansson -ldl -lpthread -lpcap 
SOURCES=glibc_overrides.c lib.c tcp_spy.c strings.c tcp_json_builder.c packet_sniffer.c 
EXECUTABLE=netspy.so
ENV=NETSPY_PATH=~/host NETSPY_TCPINFO_BYTES_IVAL=5000 NETSPY_TCPINFO_MICROS_IVAL=0 LD_PRELOAD=./$(EXECUTABLE) 

netspy:
	$(CC) $(SOURCES) $(CFLAGS) -o $(EXECUTABLE)

clean:
	rm -f *.o
	rm -f $(EXECUTABLE)
	rm -f .*.s*

curl: netspy
	$(ENV) curl -s google.com > /dev/null

angular: netspy
	$(ENV) curl -s https://ajax.googleapis.com/ajax/libs/angularjs/1.5.7/angular.min.js > /dev/null

