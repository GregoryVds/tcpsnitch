CC=gcc
DEPS=-ljansson -ldl -lpthread -lpcap -lslog
HEADERS=lib.h tcp_spy.h string_helpers.h tcp_spy_json.h packet_sniffer.h \
	logger.h init.h resizable_array.h
SOURCES=libc_overrides.c lib.c tcp_spy.c string_helpers.c tcp_spy_json.c \
	packet_sniffer.c logger.c init.c resizable_array.c 

MAJOR_VERSION=1
MINOR_VERSION=0
VERSION=$(MAJOR_VERSION).$(MINOR_VERSION)

LINKER_NAME=libnetspy.so
SONAME=$(LINKER_NAME).$(MAJOR_VERSION)
REAL_NAME=$(SONAME).$(MINOR_VERSION)

ENV=NETSPY_PATH=/home/greg/host \
    NETSPY_BYTES_IVAL=4096 \
    NETSPY_MICROS_IVAL=0 \
    LD_PRELOAD=./$(LINKER_NAME) 
#    NETSPY_DEV=enp0s3 \

ANGULAR=https://ajax.googleapis.com/ajax/libs/angularjs/1.5.7/angular.min.js 

default: netspy

netspy: $(HEADERS) $(SOURCES)
	$(CC) -g -Wall -Wextra -Werror -Wfloat-equal -Wundef -Wshadow -fPIC \
		-Wpointer-arith -Wcast-align -Wstrict-prototypes \
		-Wwrite-strings -Waggregate-return -Wcast-qual \
		-Wunreachable-code -shared -Wl,-Bsymbolic \
		-Wl,-soname,$(SONAME) -o $(REAL_NAME) $(SOURCES) $(DEPS) 
	ln -sf $(REAL_NAME) $(SONAME)
	ln -sf $(REAL_NAME) $(LINKER_NAME)

clean:
	rm -f *.o .*.s* *.so* tests/.*.s*

curl: netspy
	$(ENV) /usr/bin/curl -s google.com

angular: netspy
	$(ENV) curl -s $(ANGULAR)

firefox: netspy
	$(ENV) firefox

tests: netspy
	cd tests && rake

index: 
	ctags -R .
