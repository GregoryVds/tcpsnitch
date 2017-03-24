# Version
MAJOR_VERSION=0
MINOR_VERSION=1
VERSION=$(MAJOR_VERSION).$(MINOR_VERSION)

# Exexutable name
EXECUTABLE=tcpsnitch

# Libraries names
LINKER_NAME=libtcpsnitch.so
SONAME=$(LINKER_NAME).$(MAJOR_VERSION)
REAL_NAME=$(SONAME).$(MINOR_VERSION)
AMD64=x86_64
I386=i386
LIB_AMD64=$(REAL_NAME)-$(AMD64)
LIB_I386=$(REAL_NAME)-$(I386)
LIB_ANDROID=android-$(LINKER_NAME)

# Installation paths
BIN_PATH=$(DESTDIR)/usr/local/bin
DEPS_PATH=$(BIN_PATH)/tcpsnitch_deps
LIB_PATH=$(DESTDIR)/usr/local/lib
LIB_AMD64_PATH=$(LIB_PATH)/$(AMD64)-linux-gnu
LIB_I386_PATH=$(LIB_PATH)/$(I386)-linux-gnu

# Installation dependencies (not sure where to place those... Merge in one script?)
BIN_DEPS=./bin/$(EXECUTABLE) ./bin/$(LIB_ANDROID)

# Compiler & linker flags
CC_ANDROID?=~/android_toolchain_23/bin/arm-linux-androideabi-gcc
CC=gcc
C_FLAGS=-g -fPIC --shared -Wl,-Bsymbolic -std=c11
W_FLAGS=-Wall -Wextra -Werror -Wfloat-equal -Wundef -Wshadow -Wpointer-arith \
	-Wstrict-prototypes -Wwrite-strings -Waggregate-return -Wcast-qual \
	-Wunreachable-code
L_FLAGS=-Wl,-soname,$(SONAME)

# Dependencies
DEPS=-ljansson -ldl -lpthread -lpcap 
DEPS_ANDROID=-ldl -llog -ljansson -lpcap

# Source files
HEADERS=lib.h sock_events.h string_builders.h json_builder.h packet_sniffer.h \
	logger.h init.h resizable_array.h verbose_mode.h
SOURCES=libc_overrides.c lib.c sock_events.c string_builders.c json_builder.c \
	packet_sniffer.c logger.c init.c resizable_array.c verbose_mode.c \

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

default: linux

configure:
	@echo "[-] Checking presence of library dependencies..."
	@$(call check_lib,libjansson,$(EJANSSON))
	@$(call check_lib,libpcap,$(EPCAP))
	@echo "[-] Checking presence of both 32 bits & 64 bits versions..."
	@$(call check_version,libjansson,$(AMD64))
	@$(call check_version,libjansson,$(I386))
	@$(call check_version,libpcap,$(AMD64))
	@$(call check_version,libpcap,$(I386))
	@echo "[-] Ok! Dependencies present."
	@echo "[-] Issue \"make && make install\" to compile & install $(EXECUTABLE)."

linux: $(HEADERS) $(SOURCES)
	@echo "[-] Compiling Linux 64 bits lib version..."
	@$(CC) $(C_FLAGS) $(W_FLAGS) $(L_FLAGS) -o ./bin/$(LIB_AMD64) $(SOURCES) $(DEPS)
	@echo "[-] Compiling Linux 32 bits lib version..."
	@$(CC) $(C_FLAGS) -m32 $(W_FLAGS) $(L_FLAGS) -o ./bin/$(LIB_I386) $(SOURCES) $(DEPS) 

android: $(HEADERS) $(SOURCES)
	@echo "[-] Compiling Android lib version..."
	@$(CC_ANDROID) $(C_FLAGS) $(W_FLAGS) $(L_FLAGS) -o ./bin/$(LIB_ANDROID) $(SOURCES) $(DEPS_ANDROID)

install:
	@test -d $(LIB_PATH) || mkdir $(LIB_PATH)
	@test -d $(LIB_AMD64_PATH) || mkdir $(LIB_AMD64_PATH)
	@test -d $(LIB_I386_PATH) || mkdir $(LIB_I386_PATH)
	@install -m 0444 ./bin/$(LIB_AMD64) $(LIB_AMD64_PATH)/$(REAL_NAME)
	@echo "[-] Moved Linux 64 bits lib version to \"$(LIB_AMD64_PATH)\""
	@install -m 0444 ./bin/$(LIB_I386) $(LIB_I386_PATH)/$(REAL_NAME)
	@echo "[-] Moved Linux 32 bits lib version to \"$(LIB_I386_PATH)\""
	@test -d $(BIN_PATH) || mkdir $(BIN_PATH)
	@test -d $(DEPS_PATH) || mkdir $(DEPS_PATH)
	@install -m 0755 ./bin/$(EXECUTABLE) $(DEPS_PATH)
	@(test -f ./bin/$(LIB_ANDROID) && install -m 0755 ./bin/$(LIB_ANDROID) $(DEPS_PATH)) || true
	@ln -fs $(DEPS_PATH)/$(EXECUTABLE) $(BIN_PATH)/$(EXECUTABLE)
	@echo "[-] Moved executable & dependencies to \"$(DEPS_PATH)\""
	@echo "[-] Added symlink to executable in \"$(BIN_PATH)\""
	@echo "[-] Done!"

uninstall:
	@rm $(LIB_AMD64_PATH)/$(REAL_NAME)
	@rm $(LIB_I386_PATH)/$(REAL_NAME)
	@rm -rf $(DEPS_PATH)
	@rm $(BIN_PATH)/$(EXECUTABLE)

clean:
	@rm -f ./bin/*.so*

tests: linux install
	cd tests && rake

index:
	ctags -R .

.PHONY: configure tests clean index android

