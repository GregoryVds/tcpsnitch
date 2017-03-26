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

### Dependencies

#### Debian based Linux

Tested on Ubuntu 16.04.2 Xenial

```
sudo apt install libc6-dev-i386 libjansson-dev libjansson-dev:i386 libpcap0.8 libpcap0.8:i386 libpcap0.8-dev
```

#### RPM based Linux


### Compilation & installation

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
