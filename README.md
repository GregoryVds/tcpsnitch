![TCPsnitch logo](https://tcpsnitch.org/assets/logo/snitch200x120.png "TCPSnitch")

`tcpsnitch` is a tracing tool designed to investigate the interactions between an application and the TCP/IP stack. `tcpsnitch` runs the specified command until it exits and intercepts all libc function calls on internet sockets.

## Overview

To start gently, one may run the following command to trace the `curl` program:
```bash
$ tcpsnitch curl google.com
```

For each opened internet socket, `tcpsnitch` builds an ordered list of function calls (a function invocation is called an **event** in the remaining of this document). For each event, `tcpsnitch` records the arguments, the return value and various information such as the current timestamp or the thread id. Specifically, a `connect()` event might look like this in a socket trace:

```JSON
{
    "type": "connect",
    "timestamp_usec": 1491043720731853, 
    "return_value": 0, 
    "success": true, 
    "thread_id": 17313, 
    "details": {
        "addr": {
            "sa_family": "AF_INET", 
            "ip": "127.0.1.1", 
            "port": "53"
        }
    }
}
```

Socket traces are written to text files where each line is a JSON object representing a single event. The head of such a trace could like this:

```JSON
{"type": "socket", "timestamp_usec": 1491043720731840, "return_value": 6, "success": true, "thread_id": 17313, "details": {"sock_info": {"domain": "AF_INET", "type": "SOCK_DGRAM", "protocol": 0, "SOCK_CLOEXEC": false, "SOCK_NONBLOCK": true}}}
{"type": "ioctl", "timestamp_usec": 1491043720765019, "return_value": 0, "success": true, "thread_id": 17313, "details": {"request": "FIONREAD"}}
{"type": "recvfrom", "timestamp_usec": 1491043720765027, "return_value": 44, "success": true, "thread_id": 17313, "details": {"bytes": 2048, "flags": {"MSG_CMSG_CLOEXEC": false, "MSG_DONTWAIT": false, "MSG_ERRQUEUE": false, "MSG_OOB": false, "MSG_PEEK": false, "MSG_TRUNC": false, "MSG_WAITALL": false}, "addr": {"sa_family": "AF_INET", "ip": "127.0.1.1", "port": "53"}}}
{"type": "ioctl", "timestamp_usec": 1491043720770075, "return_value": 0, "success": true, "thread_id": 17313, "details": {"request": "FIONREAD"}}
{"type": "recvfrom", "timestamp_usec": 1491043720770094, "return_value": 56, "success": true, "thread_id": 17313, "details": {"bytes": 65536, "flags": {"MSG_CMSG_CLOEXEC": false, "MSG_DONTWAIT": false, "MSG_ERRQUEUE": false, "MSG_OOB": false, "MSG_PEEK": false, "MSG_TRUNC": false, "MSG_WAITALL": false}, "addr": {"sa_family": "AF_INET", "ip": "127.0.1.1", "port": "53"}}}
```

As a single command may forks multiple processes (and `tcpsnitch` follows forks), all socket traces belonging to a given process are put together in a directory, named after the traced process. Inside such a directory, socket traces are named based on the order they were opened by the process.

By default, traces are saved in a random directory under `/tmp` and automatically uploaded to www.tcpsnitch.org, a platform designed to centralize, visualize and analyze the traces. Note that all uploaded traces are public and available for anyone to consult and download.

As visible on the next code snippet, `tcpsnitch` gives you the URL at which your trace is available.

```bash
$ tcpsnitch curl google.com
Trace saved in /tmp/tmp.4ERKizKyU3.
Uploading trace....
Trace successfully uploaded at https://tcpsnitch.org/app_traces/20.
Trace archive will be imported shortly. Refresh this page in a few minutes...
```

Note that several minutes are required to import the trace (i.e. extract the trace archive and insert all the events in the database). Once imported, several more minutes may be needed to compute the quantitative analysis of the trace.

Finally, `tcpsnitch` also allows to extract the `TCP_INFO` socket option at user-defined intervals and to record a `.pcap` trace for each individual socket. See the usage section for more information.

## Compatibility

`tcpsnitch` allows tracing applications on:
- Linux 64-bit
- Android (tested on Android API 23).

As `tcpsnitch` works by intercepting calls to libc functions using the `LD_PRELOAD` environment variable, tracing cannot be performed for applications which are statically linked with libc.

Note: On Linux, Chrome (and any Chromium based app such as Electron, Opera, etc...) are known to be NOT compatible.

## Installation

For users that want to trace Android applications, scroll down to the "Compilation for Android" section.

### Dependencies

#### Debian based Linux

Tested on Ubuntu 16 & 14, Debian 8, Elementary 0.4, Mint 18

```
sudo dpkg --add-architecture i386 && sudo apt-get update && sudo apt-get install make gcc gcc-multilib libc6-dev libc6-dev:i386 libjansson-dev libjansson-dev:i386 libpcap0.8 libpcap0.8:i386 libpcap0.8-dev
```

#### RPM based Linux

Tested on Fedora 25 & CentOS 7
```bash
sudo yum install make gcc glibc-devel glibc-devel.i686 libgcc libgcc.i686 libpcap-devel.x86_64 libpcap-devel.i686 jansson jansson.i686 && curl -O http://www.digip.org/jansson/releases/jansson-2.10.tar.bz2 && bunzip2 -c jansson-2.10.tar.bz2 | tar xf - && rm -f jansson-2.10.tar.bz2 && cd jansson-2.10 && ./configure && make && sudo make install && cd .. && rm -rf jansson-2.10
```

### Compilation & installation

Build & install:

```bash
./configure
make
sudo make install
```

## Usage

Usage: `tcpsnitch [<options>] <cmd> [<cmd_args>]` where:
- `<options>` are `tcpsnitch` options
- `<cmd>` is the command to trace (mandatory)
- `<cmd_args>` are the arguments of `<cmd>`.

Here is a simple example with `curl` and all default options:
```bash
tcpsnitch curl google.com
```

One may issue `tcpsnitch -h` to get more information about the supported options. The most important ones are the following:

- `-b` and `-u` are used for extracting `TCP_INFO` at user-defined intervals. See section "Extracting `TCP_INFO`" for more info.
- `-c` is used for capturing `pcap` traces of the sockets. See section "Packet capture" for more info.
- `-a` and `-k` are used for tracing Android application. See section "Android usage" for more info.
- `-n` deactivate the automatic upload of traces.
- `-d` sets the directory in which the trace will be written (instead of a random directory in `/tmp`).
- `-f` sets the verbosity level of logs saved to file. By default, only WARN and ERROR messages are written to logs. This is mainly be useful for reporting a bug and debugging.
- `-l` is similar to `-f` but sets the log verbosity on STDOUT, which by default only shows ERROR messages. This is used for debugging purposes.
- `-t` controls the frequency at which events are dumped to file. By default, events are written to file every 1000 milliseconds.
- `-v` is pretty useless at the moment, but it is supposed to put `tcpsnitch` in verbose mode in the style of `strace`. Still to be implemented (at the moment it only display event names).

### Extracting `TCP_INFO`
`-b <bytes>` and `-u <usec>` allow to extract the value of the `TCP_INFO` socket option for each socket at user-defined intervals. Note that the `TCP_INFO` values appears as any other event in the JSON trace of the socekt. 

- With `-b <bytes>`, `TCP_INFO` is recorded every `<bytes>` sent+received on the socket.
- With `-u <usec>`, `TCP_INFO` is recorded every `<usec>` micro-seconds.
- When both options are set, `TCP_INFO` is recorded when either one of the two conditions is matched. By default this option is turned off. 

Also note that `tcpsnitch` only checks for these conditions when an overridden function is called.

### Packet capture
The `-c` option activates the capture of a `.pcap` trace for each socket. Note that you need to have the appropriate permissions to be able to capture traffic on an interface (see `man pcap` for more information about such permissions).

This feature is not available for Android at the moment.

### Android usage

The usage on Android is a two-steps process, very similar to the usage on Linux. First, `tcpsnitch` setup and launch the application to be traced with the appropriate options, then the traces are pulled from the device and copied to the host machine. 

All options are supported on Android, except the `-c` option for capture `.pcap` traces.

A few preliminary setup steps must be done once on the device:
- Enable USB Debugging on your phone: Go to Settings > About Phone > Tap on Build number 7 times > Return to Settings > Developer Options > USB Debugging.
- Plug your phone to your machine with a USB cable.
- Accept the connection on the phone.
- Isssue `adb devices` and make sure that your phone is visible (your should see `device` in the second column).

When the device is accesible via `adb`, the usage is almost the same as on Linux:

1. Issue the regular `tcpsnitch` command with the option `-a` to indicate that you want to trace an application on the connected Android device. Note that `<cmd>` argument must match the name of a package installed on the device via a simple `grep`. For instance, to trace the Firefox application whose package name is `org.firefox.com`, one may isssue `tcpsnitch -a firefox`. `tcpsnitch` will inform you of the matching package found and immediately start the application.
2. When you are done interacting with the application, issue `tcpsnitch -k <package>` to kill the application and terminate the tracing process. The traces will be pulled from the device and saved on your disk in `/tmp` before being uploaded to www.tcpsnitch.org.

**Important:** you must restart your Android device to completely deactivate the tracing. As `tcpsnitch` uses Android properties to setup the `LD_PRELOAD` library, and these properties cannot be unset, rebooting the device must be done to remove the properties (maybe someone knows a better solution?).

Here is a full example for tracing Firefox:
```bash
$ tcpsnitch -a firefox
Found Android package: 'org.mozilla.firefox'.
Uploading tcpsnitch library to /data/libtcpsnitch.so.0.1-arm.
Start package 'org.mozilla.firefox'.
Execute './tcpsnitch -k firefox' to terminate the capture.
# INTERACTING WITH APPLICATION
$ tcpsnitch -k firefox
Found Android package: 'org.mozilla.firefox'.
Pulling trace from Android device....
Trace saved in /tmp/tmp.MidCH9rm3x.
Uploading trace....
Trace successfully uploaded at https://tcpsnitch.org/app_traces/21.
Trace archive will be imported shortly. Refresh this page in a few minutes...
```

Note that in case of multiple matches for a package, the first matched package will be used. You might thus need to be more specific to avoid conflicts. You can execute `adb shell pm list packages` to get the name of all packages installed on your device.

Also note that a single device must be visible to `adb`.

## Compilation for Android

In order to trace Android applications, `tcpsnitch` must be compiled with the [Android Native Development Kit](https://developer.android.com/ndk/index.html) (NDK). The compilation is more involved and the setup requires a rooted Android device.

Basically, it involves the following steps:
- [Download](https://developer.android.com/ndk/index.html) the Android NDK.
- Generate a [standalone toolchain](https://developer.android.com/ndk/index.html) for the processor architecture & the Android API of your device.
- Compile `libjansson` and `libpcap` with the NDK, and make the compiled librairies and the header files available to the standalone toolchain.
- Fix a buggy C header in the NDK.
- Compile `tcpsnitch` with the standalone toolchain and prepare the Android device.

The following section gives a complexte example that walks you through all the steps.

#### Compilation walk-through

A few assumption:
- You have downloaded the NDK and extracted it to `<NDK_PATH>`.
- This repository is located at `<TCPSNITCH_PATH>`.

First, let's define a few variables:
```
export TCPSNITCH=<TCPSNITCH_PATH>
export NDK=<NDK_PATH>
# Where the standalone toolchain WILL be created
export TOOLCHAIN=<TOOLCHAIN_PATH>
```

Now, let's start by generating a standalone toolchain for an ARM device running Android API 23 (version 6.0, Marshmallow). The mapping between Android versions and API levels at the following [page](https://source.android.com/source/build-numbers.html).

```
$NDK/build/tools/make_standalone_toolchain.py --arch arm --api 23 --install-dir $TOOLCHAIN
```

We now must compile both `libjansson` and `libpcap` with the NDK. When this is done, we must install their header files and the compiled librairies in the "sysroot" in our standalone toolchain.

Lets start with `libjansson`:
```
git clone https://github.com/akheron/jansson && cd jansson
# Configuration file which we don't use, we may leave it empty
touch src/jansson_private_config.h
sed -i 's/BUILD_SHARED_LIBRARY/BUILD_STATIC_LIBRARY/g' Android.mk
$NDK/ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk
cp obj/local/armeabi/libjansson.a $TOOLCHAIN/sysroot/usr/lib/
cp src/jansson.h android/jansson_config.h $TOOLCHAIN/sysroot/usr/include/
cd .. && rm -rf jansson
```

Now, let's tackle `libpcap`:
```
git clone https://github.com/the-tcpdump-group/libpcap && cd libpcap
export CC=$TOOLCHAIN/bin/arm-linux-androideabi-gcc
./configure --host=arm-linux --with-pcap=linux --prefix=/usr
# You will need to install some missing dependencies (e.g. `flex` & `bison`)
sudo apt-get install flex bison
# Reissue ./configure untill all dependencies are met
./configure --host=arm-linux --with-pcap=linux --prefix=/usr
# Compile && install in toolchain
make && sudo make install DESTDIR=$TOOLCHAIN/sysroot
cd .. && rm -rf libpcap
```

We are now ready to compile `tcpsnitch`:
```
# First, let's fix the buggy `tcp.h` header from the NDK
sed -i 's/include <linux\/tcp.h>/include <sys\/cdefs.h>\n#include <linux\/tcp.h>/g' $TOOLCHAIN/sysroot/usr/include/netinet/tcp.h
# Configure the compiler
export CC_ANDROID=$TOOLCHAIN/bin/arm-linux-androideabi-gcc
# Build & install tcpsnitch
make android && sudo make install
```

You are ready to go! See Android usage section for how to start tracing applications.

## FAQ

### How does it work?

An interesting feature of the Linux dynamic linker (`ld.so`) is the ability to link user-specified shared librairies before the librairies specified in the list of dependencies of a program. This feature can be controlled with the `LD_PRELOAD` environment variable which contains a (possibly empty) list of additional user-specified librairies. In particular, this `LD_PRELOAD` variable may force the dynamic linker to link a user-specified shared library before the `libc` library. As a result, any function defined in this user-specified library take precedence over a function with the same signature defined in `libc`.

The implication here is that it allows to intercept calls to system call wrapper functions. We merely have to add a custom shared library that redefines these system call wrappers functions to `LD_PRELOAD`. Such a shim library then transparently intercept the `libc` function calls and perform some processing before calling the original `libc` wrapper functions.

### What are these `wrong ELF class` errors?

Nothing bad, these can ignored. The `tcpsnitch` shared library is compiled for both the 32-bit and 64-bit architectures. When tracing a command, both librairies are loaded in the `LD_PRELOAD`environment variable since there is no easy way to know the architecture of the command binary (often it is a shell script executing another binary). The dynamic linker then takes care of loading the compatible library and ignore the second one (but still throws an error).

## Contact

Come discuss about `tcpsnitch` at https://gitter.im/Tcpsnitch.

The author's email is gregory.vanderschueren[at]gmail.com
