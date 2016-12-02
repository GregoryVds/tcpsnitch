CC=gcc
DEPS=-ljansson -ldl -lpthread -lpcap 
HEADERS=lib.h tcp_spy.h string_helpers.h tcp_spy_json.h packet_sniffer.h \
	logger.h init.h resizable_array.h verbose_mode.h
SOURCES=libc_overrides.c lib.c tcp_spy.c string_helpers.c tcp_spy_json.c \
	packet_sniffer.c logger.c init.c resizable_array.c verbose_mode.c 

MAJOR_VERSION=1
MINOR_VERSION=0
VERSION=$(MAJOR_VERSION).$(MINOR_VERSION)

LINKER_NAME=libtcpsnitch.so
SONAME=$(LINKER_NAME).$(MAJOR_VERSION)
REAL_NAME=$(SONAME).$(MINOR_VERSION)

EXECUTABLE=tcpsnitch

INSTALL_PATH=/usr/local
LIB_PATH=$(INSTALL_PATH)/lib
BIN_PATH=$(INSTALL_PATH)/bin

default: tcpsnitch

tcpsnitch: $(HEADERS) $(SOURCES)
	$(CC) -g -Wall -Wextra -Werror -Wfloat-equal -Wundef -Wshadow -fPIC \
		-Wpointer-arith -Wcast-align -Wstrict-prototypes \
		-Wwrite-strings -Waggregate-return -Wcast-qual \
		-Wunreachable-code -shared -Wl,-Bsymbolic \
		-Wl,-soname,$(SONAME) -o $(REAL_NAME) $(SOURCES) $(DEPS) 

install:
	@test -d $(BIN_PATH) || mkdir $(BIN_PATH)
	@install -m 0755 $(EXECUTABLE) $(BIN_PATH) 
	@test -d $(LIB_PATH) || mkdir $(LIB_PATH)
	@install -m 0644 $(REAL_NAME) $(LIB_PATH)
	@ln -fs $(LIB_PATH)/$(REAL_NAME) $(LIB_PATH)/$(SONAME) 
	@ln -fs $(LIB_PATH)/$(SONAME) $(LIB_PATH)/$(LINKER_NAME)

uninstall:
	@rm $(BIN_PATH)/$(EXECUTABLE)
	@rm $(LIB_PATH)/$(LINKER_NAME)
	@rm $(LIB_PATH)/$(SONAME)
	@rm $(LIB_PATH)/$(REAL_NAME)

clean:
	rm -f *.o .*.s* *.so* tests/.*.s*

tests: tcpsnitch
	cd tests && rake

index: 
	ctags -R .

.PHONY: tcpsnitch tests clean index

