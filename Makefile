# Version
MAJOR_VERSION=0
MINOR_VERSION=1
VERSION=$(MAJOR_VERSION).$(MINOR_VERSION)

CONFIG=.config.in

# ./bin names
EXECUTABLE=tcpsnitch
BASE_NAME=lib$(EXECUTABLE).so.$(VERSION)
AMD64=x86-64
I386=i386
ARM=arm
LIB_AMD64=$(BASE_NAME)-$(AMD64)
LIB_I386=$(BASE_NAME)-$(I386)
LIB_ARM=$(BASE_NAME)-$(ARM)
LINUX_GIT_HASH=linux_git_hash
ANDROID_GIT_HASH=android_git_hash
ENABLE_I386=enable_i386

# Installation paths
BIN_PATH=$(DESTDIR)/usr/local/bin
DEPS_PATH=$(BIN_PATH)/tcpsnitch_deps

# Compiler & linker flags
CC=gcc
C_FLAGS=-g -fPIC --shared -Wl,-Bsymbolic -std=c11 -fvisibility=hidden
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
DEBIAN_BASED_DEPS=-lpthread -ldl -ljansson -l:libpcap.so.0.8
# Note: On Centos, there is no "jansson.devel" pacakge available. Thus for ease
# of installation, we specify the library name.
RPM_BASED_DEPS=-lpthread -ldl -l:libjansson.so.4 -lpcap
# Fallback to standard names for other distributions
OTHER_DEPS=-lpthread -ldl -lpcap -ljansson
LINUX_DEPS=$(shell if rpm -q -f /usr/bin/rpm >/dev/null 2>&1; then echo $(RPM_BASED_DEPS); elif type apt-get >/dev/null 2>&1; then echo $(DEBIAN_BASED_DEPS); else echo $(OTHER_DEPS); fi)

# Source files
HEADERS=lib.h sock_events.h string_builders.h json_builder.h packet_sniffer.h \
	logger.h init.h resizable_array.h verbose_mode.h constants.h
SOURCES=libc_overrides.c lib.c sock_events.c string_builders.c json_builder.c \
	packet_sniffer.c logger.c init.c resizable_array.c verbose_mode.c \
	constants.c

# $(1) is file name, $(2) is config value
define set_file_opt
	echo $(2) > bin/$(1)
endef

default: linux

linux: $(CONFIG) $(HEADERS) $(SOURCES)
	@echo "[-] Compiling Linux 64-bit lib version..."
	@$(CC) $(C_FLAGS) $(W_FLAGS) $(L_FLAGS) -o ./bin/$(LIB_AMD64) $(SOURCES) $(LINUX_DEPS)
	@if grep supports_i386=true .config.in >/dev/null 2>&1; then\
		echo "[-] Compiling Linux 32-bit lib version...";\
		$(CC) $(C_FLAGS) -m32 $(W_FLAGS) $(L_FLAGS) -o ./bin/$(LIB_I386) $(SOURCES) $(LINUX_DEPS);\
		$(call set_file_opt,$(ENABLE_I386),true);\
	else\
		echo "[-] 32-bit support is disabled.";\
		$(call set_file_opt,$(ENABLE_I386),false);\
	fi
	@$(call set_file_opt,$(LINUX_GIT_HASH),$(shell git rev-parse HEAD))

android: $(HEADERS) $(SOURCES)
ifndef CC_ANDROID
	$(error CC_ANDROID variable not set. See README for compilation instructions)
endif
	@echo "[-] Compiling Android lib version..."
	@$(CC_ANDROID) $(C_FLAGS) $(W_FLAGS) $(L_FLAGS) -o ./bin/$(LIB_ARM) $(SOURCES) -Wl,-Bstatic -ljansson -lpcap -Wl,-Bdynamic -ldl -llog
	@$(call set_file_opt,$(ANDROID_GIT_HASH),$(shell git rev-parse HEAD))

install:
	mkdir -p $(DEPS_PATH)
	install -m 0444 ./bin/* $(DEPS_PATH)
	chmod 0755 $(DEPS_PATH)/$(EXECUTABLE)
	ln -fs ./tcpsnitch_deps/$(EXECUTABLE) $(BIN_PATH)/$(EXECUTABLE)

uninstall:
	@rm -rf $(DEPS_PATH)
	@rm $(BIN_PATH)/$(EXECUTABLE)

clean:
	@rm -f ./bin/*.so* *hash $(CONFIG)

tests: linux install
	cd tests && rake

index:
	ctags -R .

$(CONFIG):
	@test -f $(CONFIG) || ./configure

.PHONY: configure tests clean index android $(CONFIG)
