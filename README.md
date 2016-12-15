# Tcpsnitch

WORK IN PROGRESS, (most probably) not ready for use.

## Overview

Tcpsnitch is a program that helps investigate the interactions between an application, the TCP stack and the network. It runs the specified command until it exits and records useful information for each TCP connection:
- The system calls made along with their arguments and return value.
- The value of the TCP\_INFO socket option at user-defined intervals to provide information about the state of a TCP connection in the kernel.
- A pcap trace of all the packets sent/received.
- Aggregate information about the TCP connection such as the number of syscalls made or bytes sent/received.

## Compatibility

Comptabible with Linux only (tested on Ubuntu & Elementary only).

The following applications have been tested and are compatible: Firefox, Epiphany, VLC, Steam, Transmission, QbitTorrent, Spotify, Dropbox, x2goclient..

The following applications are NOT compatible: Chrome, any Chromium based app such as Opera, Electron..

## Intallation

### Requirements

Require the following libraries (both 32 bits and 64 bits versions):
- jansson library (www.digip.org/jansson)
- pcap library (http://www.tcpdump.org/)

### Ubuntu Linux x64

#### Multiarch

We compile the tcpsnitch library in both 32 bits and 64 bits versions in order to support both types of executables. 
This implies that each dependency must be met with both the 32 bits and 64 bits versions.

You might need to add the i386 architecture to dpkg for installing such packages on a x64 machine: `sudo dpkg --add-architecture i386`.
Then Run `sudo apt-get update` to refresh the package cache with the newly added architecture

#### Libs

For `libjansson`, simply install both versions with: `sudo apt-get install libjansson-dev libjansson-dev:i386`.

For `libpcap`, a bit more work is needed as this library is not multiarch compatible. The devel package of one architecture conflicts with the package of the other architecture, so we CANNOT simply perform `sudo apt-get install libpcap0.8-dev libpcap0.8-dev:i386`. A trick is to install the devel version for one architecture, and the regular lib version for the other architecture. We then need to manually create the symlink for the "linker name" of the library:

Run `sudo apt-get install libpcap0.8-dev libpcap0.8:i386`.
Then `sudo ln -s /usr/lib/i386-linux-gnu/libpcap.so.0.8 /usr/lib/i386-linux-gnu/libpcap.so`.

If `make checkdeps` does not throw an error, this is a sign that you are in good shape for the compilation.

#### Compilation & installation

Finally run `make install` & `sudo make install`.

## Usage

To run tcpsnitch with curl and defaults options: `sudo tcpsnitch curl google.com`. 

To see verbose output and choose the log directory: `sudo tcpsnitch -v -d <path> curl google.com`.

See `tcpsnitch -h` for more information about the options.

## How it works?

## FAQ

### What are these ELF errors that get thrown?

When running tcpsnitch, you will get the following errors:
`ERROR: ld.so: object '/usr/local/lib/i386-linux-gnu/libtcpsnitch.so.1.0' from `LD\_PRELOAD` cannot be preloaded (wrong ELF class: ELFCLASS32): ignored.`

On a x64 machine, tcpsnitch must support both 32 bits and 64 bits executables. For instance, a 32 bits application such as Steam might fork and execute 64 bits applications. We thus always add both versions of the library in the `LD\_PRELOAD` variable to support both cases. This means that for any process running with tcpsnitch, there will always be one library which is not supported, and one which is supported.

## Contact

The author's email is gregory.vanderschueren[at]gmail.com
