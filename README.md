# Tcpsnitch

## Overview

Tcpsnitch is a tracing tool that helps investigate the interactions between an application, the TCP stack and the network. It runs the specified command until it exits and records all invokations of functions from the socket API.

## Compatibility

Tcpsnitch allows tracing applications on:
- Linux (tested on Ubuntu 16.04, Debian 8.6, CentOS 7, Fedora 25).
- Android (tested on Android API 23).

Note: On Linux, the following applications are NOT compatible: Chrome and any Chromium based app such as Electron, Opera, etc.

## Intallation

For users that want to trace Android applications, go down to the "Setup for Android" section.

### Dependencies

#### Debian based Linux

Tested on Ubuntu 16 & Debian 8

```
sudo dpkg --add-architecture i386 && sudo apt-get update && sudo apt install gcc make libc6-dev libc6-dev-i386 libjansson-dev libjansson-dev:i386 libpcap0.8 libpcap0.8:i386 libpcap0.8-dev
```

#### RPM based Linux

Tested on Fedora 25 & CentOS 7
```
sudo yum install make gcc glibc-devel glibc-devel.i686 libgcc libgcc.i686 libpcap-devel.x86_64 libpcap-devel.i686 jansson jansson.i686 && curl -O http://www.digip.org/jansson/releases/jansson-2.10.tar.bz2 && bunzip2 -c jansson-2.10.tar.bz2 | tar xf - && rm -f jansson-2.10.tar.bz2 && cd jansson-2.10 && ./configure && make && sudo make install && cd .. && rm -rf jansson-2.10
```

### Compilation & installation

Build & install:

```
make && sudo make install
```

## Usage

### Linux

To run tcpsnitch with curl and defaults options: `tcpsnitch curl google.com`.

See `tcpsnitch -h` for more information about the options.

### Android

Accepts a single argument which should match a package installed on the Android device via a simple `grep`. In case of multiple matches, the first matched package will be used.

For instance, run `setup_app air` would match the `com.airbnb.android` package.

## Compilation & setup for Android

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

TODO:
- Upload compiled librairies on the Device.
- Install `busybox` on the Device.

## How it works?

An interesting feature of the Linux dynamic linker (`ld.so`) is the ability to link user-specified shared librairies before the librairies specified in the list of dependencies of a program. This feature can be controlled with the `LD_PRELOAD` environment variable which contains a (possibly empty) list of additional user-specified librairies. In particular, this `LD_PRELOAD` variable may force the dynamic linker to link a user-specified shared library before the `libc` library. As a result, any function defined in this user-specified library would take precedence over a function with the same signature defined in `libc`.

The implication here is that it allows to intercept calls to system call wrapper functions: we merely have to add to the `LD_PRELOAD` environment variable a custom shared library that redefines these system call wrappers functions. Such a shim library would transparently intercept the `libc` function calls and perform some processing before calling the original `libc` wrapper functions.

## FAQ

## Contact

The author's email is gregory.vanderschueren[at]gmail.com
