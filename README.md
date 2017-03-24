# Tcpsnitch

## Overview

Tcpsnitch is a program that helps investigate the interactions between an application, the TCP stack and the network. It runs the specified command until it exits and records useful information for each TCP connection:
- The system calls made along with their arguments and return value.
- The value of the TCP\_INFO socket option at user-defined intervals to provide information about the state of a TCP connection in the kernel.
- A pcap trace of all the packets sent/received.

## Compatibility

Comptabible with Linux & Android (tested on Ubuntu & Elementary only).

The following applications have been tested and are compatible: Firefox, Epiphany, VLC, Steam, Transmission, QbitTorrent, Spotify, Dropbox, x2goclient..

The following applications are NOT compatible: Chrome, any Chromium based app such as Opera, Electron..

## Intallation

### Requirements

Require the following libraries (both 32 bits and 64 bits versions):
- jansson library (www.digip.org/jansson)
- pcap library (http://www.tcpdump.org/)

### Ubuntu Linux x64

#### Multiarch

We compile the tcpsnitch library in both 32 bits and 64 bits versions in order to support both types of executables (this implies that each dependency must be met with both the 32 bits and 64 bits versions).

You might need to add the i386 architecture to dpkg for installing such packages on a x64 machine (you then have to refresh the package cache with the newly added architecture). You will also need `gcc-multilib`.

```
sudo dpkg --add-architecture i386 && sudo apt-get update
sudo apt-get install gcc-multilib
```

#### Libs

For `libjansson`, simply install both versions:
```
sudo apt-get install libjansson-dev libjansson-dev:i386 
```

For `libpcap` a bit more work is needed as this library is not multiarch compatible (the devel package of one architecture conflicts with the package of the other architecture). Thus thus CANNOT simply perform:
```
sudo apt-get install libpcap0.8-dev libpcap0.8-dev:i386
``` 

A trick is to first install each package separately such that APT takes care for you of satisfying all dependencies. Then when the second install has removed the 32 bits version, we manually recreate the symlink for the "linker name" of the 32 bits library:

```
sudo apt-get install libpcap0.8:i386
sudo apt-get install libpcap0.8-dev
sudo ln -s /usr/lib/i386-linux-gnu/libpcap.so.0.8 /usr/lib/i386-linux-gnu/libpcap.so
```

If `make checkdeps` does not throw an error, this is a sign that you are in good shape for the compilation.

#### Compilation & installation

Finally run: 
```
make
sudo make install
```

### Android

tcpsnitch has been sucessfully compiled with the NDK for Android API 23.

You must set the `CC_ANDROID`, pointing the the Android NDK compiler, before issuing make.

a single argument which should match a package installed on the Android device via a simple `grep`. In case of multiple matches, the first matched package will be used.

For instance, run `setup_app air` would match the `com.airbnb.android` package.

You need to install `busybox` on the device.
## Usage

To run tcpsnitch with curl and defaults options: `tcpsnitch curl google.com`.

See `tcpsnitch -h` for more information about the options.

## How it works?

## FAQ

## Contact

The author's email is gregory.vanderschueren[at]gmail.com
