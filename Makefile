CC=gcc
DEPS=-ljansson -ldl -lpthread -lpcap 
HEADERS=lib.h tcp_spy.h string_helpers.h tcp_spy_json.h packet_sniffer.h \
	logger.h
SOURCES=glibc_overrides.c lib.c tcp_spy.c string_helpers.c tcp_spy_json.c \
	packet_sniffer.c logger.c 

MAJOR_VERSION=1
MINOR_VERSION=0
VERSION=$(MAJOR_VERSION).$(MINOR_VERSION)

LINKER_NAME=libnetspy.so
SONAME=$(LINKER_NAME).$(MAJOR_VERSION)
REAL_NAME=$(SONAME).$(MINOR_VERSION)

ENV=NETSPY_PATH=~/host \
    NETSPY_TCPINFO_BYTES_IVAL=5000 \
    NETSPY_TCPINFO_MICROS_IVAL=0 \
    LD_PRELOAD=./$(LINKER_NAME) 

ANGULAR=https://ajax.googleapis.com/ajax/libs/angularjs/1.5.7/angular.min.js 

default: netspy

netspy: $(HEADERS) $(SOURCES)
	$(CC) -g -Wall -fPIC -shared -Wl,-Bsymbolic -Wl,-soname,$(SONAME) \
		-o $(REAL_NAME) $(SOURCES) $(DEPS) 
	ln -sf $(REAL_NAME) $(SONAME)
	ln -sf $(REAL_NAME) $(LINKER_NAME)

clean:
	rm -f *.o
	rm -f .*.s*
	rm -f *.so*

curl: netspy
	$(ENV) curl -s google.com > /dev/null

angular: netspy
	$(ENV) curl -s $(ANGULAR) > /dev/null

