# Version
MAJOR_VERSION=0
MINOR_VERSION=1
VERSION=$(MAJOR_VERSION).$(MINOR_VERSION)

# ./bin names
EXECUTABLE=tcpsnitch

BASE_NAME=lib$(EXECUTABLE).so.$(VERSION)
AMD64=x86-64
I386=i386
ARM=arm
LIB_AMD64=$(BASE_NAME)-$(subst -,_,$(AMD64))
LIB_I386=$(BASE_NAME)-$(I386)
LIB_ARM=$(BASE_NAME)-$(ARM)

LINUX_GIT_HASH=linux_git_hash
ANDROID_GIT_HASH=android_git_hash

# Installation paths
BIN_PATH=$(DESTDIR)/usr/local/bin
DEPS_PATH=$(BIN_PATH)/tcpsnitch_deps

# Compiler & linker flags
CC=gcc
C_FLAGS=-g -fPIC --shared -Wl,-Bsymbolic -std=c11
W_FLAGS=-Wall -Wextra -Werror -Wfloat-equal -Wshadow -Wpointer-arith \
	-Wstrict-prototypes -Wwrite-strings -Waggregate-return -Wcast-qual \
	-Wunreachable-code

# Dependencies
# Note: The Debian packages "libpcap0.8-dev" and "libpcap0.8-dev:i386" are
# incompatible. The header files contained in both packages are the same, the
# packages are incompatible only because of a helper script used to generate
# compiler flags, which we dont use anyway. We thus only need to install for a
# single architecture and we must specify the library name explicitly since we
# will miss the linker name symlink for the other architecture.
DEBIAN_BASED_DEPS=-ljansson -ldl -lpthread -l:libpcap.so.0.8
# Note: On Centos, there is no "jansson.devel" pacakge available. Thus for ease
# of installation, we specify the library name.
RPM_BASED_DEPS=-l:libjansson.so.4 -ldl -lpthread -lpcap
# Fallback to standard names for other distributions
OTHER_DEPS=-lpthread -ldl -lpcap -ljansson
LINUX_DEPS=$(shell if type rpm &>/dev/null; then echo $(RPM_BASED_DEPS); elif type apt-get &> /dev/null; then echo $(DEBIAN_BASED_DEPS); else echo $(OTHER_DEPS); fi)

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
	$(CC) $(C_FLAGS) $(W_FLAGS) $(L_FLAGS) -o ./bin/$(LIB_AMD64) $(SOURCES) $(LINUX_DEPS)
	@echo "[-] Compiling Linux 32 bits lib version..."
	$(CC) $(C_FLAGS) -m32 $(W_FLAGS) $(L_FLAGS) -o ./bin/$(LIB_I386) $(SOURCES) $(LINUX_DEPS)
	@git rev-parse HEAD > ./bin/$(LINUX_GIT_HASH)

android: $(HEADERS) $(SOURCES)
ifndef CC_ANDROID
	$(error CC_ANDROID variable not set. See README for compilation instructions)
endif
	@echo "[-] Compiling Android lib version..."
	$(CC_ANDROID) $(C_FLAGS) $(W_FLAGS) $(L_FLAGS) -o ./bin/$(LIB_ARM) $(SOURCES) -Wl,-Bstatic -ljansson -lpcap -Wl,-Bdynamic -ldl -llog
	@git rev-parse HEAD > ./bin/$(ANDROID_GIT_HASH)

install:
	mkdir -p $(DEPS_PATH)
	install -m 0444 ./bin/* $(DEPS_PATH)
	chmod 0755 $(DEPS_PATH)/$(EXECUTABLE)
	ln -fs ./tcpsnitch_deps/$(EXECUTABLE) $(BIN_PATH)/$(EXECUTABLE)

uninstall:
	@rm -rf $(DEPS_PATH)
	@rm $(BIN_PATH)/$(EXECUTABLE)

clean:
	@rm -f ./bin/*.so* *hash

tests: linux install
	cd tests && rake

index:
	ctags -R .

.PHONY: configure tests clean index android

