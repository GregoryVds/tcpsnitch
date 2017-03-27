# Tcpsnitch

## Overview

Tcpsnitch is a tracing tool that helps investigate the interactions between an application, the TCP stack and the network. It runs the specified command until it exits and records all invokations of functions from the socket API.

## Compatibility

Tcpsnitch allows tracing applications on:
- Linux (tested on Ubuntu 16.04, Debian 8.6, CentOS 7, Fedora 25).
- Android (tested on Android API 23).

Note: On Linux, the following applications are NOT compatible: Chrome and any Chromium based app such as Electron, Opera, etc.

## Intallation

For users that only want to trace Linux applications, you may skip the "Setup for Android" part.

### Setup for Android

In order to trace Android applications, tcpsnitch must be compiled with the Android Native Development Kit (NDK). 
The setup is is bit more involved and requires a rooted Android device.

The setup involves the following steps:
- Download the Android NDK (see https://developer.android.com/ndk/downloads).
- Generate a standalone toolchain for the processor architecture & Android API of your device (see https://developer.android.com/ndk/guides/standalone_toolchain.html).
- Compile libjansson and libpcap with the NDK and install their header files in the sysroot of your standalone toolchain.

You need to install `busybox` on the device.

### Dependencies

#### Debian based Linux

Tested on Ubuntu 16.04 Xenial & Debian 8.6 Jessie

```
sudo dpkg --add-architecture i386 && sudo apt-get update && sudo apt install gcc make libc6-dev libc6-dev-i386 libjansson-dev libjansson-dev:i386 libpcap0.8 libpcap0.8:i386 libpcap0.8-dev
```

#### RPM based Linux

Tested on Fedora 25 & CentOS 7
```
sudo yum install make gcc glibc-devel glibc-devel.i686 libgcc libgcc.i686 libpcap-devel.x86_64 libpcap-devel.i686 jansson jansson.i686 && curl -O http://www.digip.org/jansson/releases/jansson-2.10.tar.bz2 && bunzip2 -c jansson-2.10.tar.bz2 | tar xf - && rm -f jansson-2.10.tar.bz2 && cd jansson-2.10 && ./configure && make && sudo make install && cd .. && rm -rf jansson-2.10
```

### Compilation & installation

For tracing on Linux:

```
make
```

For tracing on Android, set the `CC_ANDROID` environment variable to point to the Android NDK compiler. Then, issue:
```
make android
```

Then
```
sudo make install
```

## Usage

### Linux

To run tcpsnitch with curl and defaults options: `tcpsnitch curl google.com`.

See `tcpsnitch -h` for more information about the options.

### Android

Accepts a single argument which should match a package installed on the Android device via a simple `grep`. In case of multiple matches, the first matched package will be used.

For instance, run `setup_app air` would match the `com.airbnb.android` package.


## How it works?

## FAQ

## Contact

The author's email is gregory.vanderschueren[at]gmail.com
