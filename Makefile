MAJOR_VERSION=1
MINOR_VERSION=0
VERSION=$(MAJOR_VERSION).$(MINOR_VERSION)

LINKER_NAME=libtcpsnitch.so
SONAME=$(LINKER_NAME).$(MAJOR_VERSION)
REAL_NAME=$(SONAME).$(MINOR_VERSION)

EXECUTABLE=tcpsnitch
AMD64=x86_64
I386=i386
INSTALL_PATH=/usr/local
BIN_PATH=$(INSTALL_PATH)/bin
LIB_PATH=$(INSTALL_PATH)/lib

# Multi-arch
LIB_AMD64_PATH=$(LIB_PATH)/$(AMD64)-linux-gnu
LIB_I386_PATH=$(LIB_PATH)/$(I386)-linux-gnu
LIB_AMD64=$(REAL_NAME)-$(AMD64)
LIB_I386=$(REAL_NAME)-$(I386)

CC_ANDROID=../android_toolchain/bin/arm-linux-androideabi-gcc-4.9
CC=gcc
C_FLAGS=-g -fPIC --shared -Wl,-Bsymbolic -std=c11
W_FLAGS=-Wall -Wextra -Werror -Wfloat-equal -Wundef -Wshadow -Wpointer-arith \
	-Wcast-align -Wstrict-prototypes -Wwrite-strings -Waggregate-return \
	-Wcast-qual -Wunreachable-code 
L_FLAGS=-Wl,-soname,$(SONAME) 


DEPS=-ljansson -ldl -lpthread -lpcap 
HEADERS=lib.h tcp_events.h string_builders.h json_builder.h packet_sniffer.h \
	logger.h init.h resizable_array.h verbose_mode.h
SOURCES=libc_overrides.c lib.c tcp_events.c string_builders.c json_builder.c \
	packet_sniffer.c logger.c init.c resizable_array.c verbose_mode.c 

# Error messages
M_LIB=Error: missing library dependency
EJANSSON=$(M_LIB) libjansson (see www.digip.org/jansson)
EPCAP=$(M_LIB) pcap (see www.tcpdump.org)
M_LIB_V=Error: missing library version

# $(1) is lib name, $(2) is version
define missing_version
	(echo "$(M_LIB_V): $(2) version of $(1)." && false)
endef

define check_version
	(ldconfig -p | grep $(1) | grep $(2) >/dev/null) || $(call missing_version,$(1),$(2))
endef

# $(1) is lib name, $(2) is error message
define check_lib
	(ldconfig -p | grep $(1) > /dev/null) || (echo "$(2)" && false)
endef

default: tcpsnitch

checkdeps:
	@echo "[-] Checking presence of library dependencies..."
	@$(call check_lib,libjansson,$(EJANSSON))
	@$(call check_lib,libpcap,$(EPCAP))
	@echo "[-] Checking presence of both 32 bits & 64 bits versions..."
	@$(call check_version,libjansson,$(AMD64))
	@$(call check_version,libjansson,$(I386))
	@$(call check_version,libpcap,$(AMD64))
	@$(call check_version,libpcap,$(I386))

tcpsnitch: checkdeps $(HEADERS) $(SOURCES)
	@echo "[-] Compiling 64 bits version..."
	$(CC) $(C_FLAGS) $(W_FLAGS) $(L_FLAGS) -o $(LIB_AMD64) $(SOURCES) $(DEPS) 
	@echo "[-] Compiling 32 bits version..."
	$(CC) $(C_FLAGS) -m32 $(W_FLAGS) $(L_FLAGS) -o $(LIB_I386) $(SOURCES) $(DEPS) 
	@echo "[-] Done!"

android:
	$(CC_ANDROID) $(C_FLAGS) $(W_FLAGS) $(L_FLAGS) -o $(LIB_AMD64) $(SOURCES) $(DEPS) 
install:
	@test -d $(LIB_PATH) || mkdir $(LIB_PATH)
	@test -d $(LIB_AMD64_PATH) || mkdir $(LIB_AMD64_PATH) 
	@test -d $(LIB_I386_PATH) || mkdir $(LIB_I386_PATH)
	@echo "[-] Move 64 bits lib version to $(LIB_AMD64_PATH)..." 
	@install -m 0644 $(LIB_AMD64) $(LIB_AMD64_PATH)/$(REAL_NAME)
	@echo "[-] Move 32 bits lib version to $(LIB_I386_PATH)..." 
	@install -m 0644 $(LIB_I386) $(LIB_I386_PATH)/$(REAL_NAME)
	@test -d $(BIN_PATH) || mkdir $(BIN_PATH)
	@echo "[-] Move executable to $(BIN_PATH)..."
	@install -m 0755 $(EXECUTABLE) $(BIN_PATH) 
	@echo "[-] Done!"

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

