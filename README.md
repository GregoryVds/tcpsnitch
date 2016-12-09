# Tcpsnitch

WORK IN PROGRESS, (MOST PROBABLY) NOT READY FOR USE!

## Overview

Tcpsnitch is a program that helps investigate the interactions between an application, the TCP stack and the network. It runs the specified command until it exits and records useful information for each TCP connection:
- The system calls made along with their arguments and return value.
- The value of the TCP\_INFO socket option at user-defined intervals to provide information about the state of a TCP connection in the kernel.
- A pcap trace of all the packets sent/received.
- Aggregate information about the TCP connection such as the number of syscalls made or bytes sent/received.

## Intallation

### Requirements

Require the following libraries:
- jansson library (www.digip.org/jansson)
- pcap library (http://www.tcpdump.org/)

Require the `pcap.h` header file (available with the `libpcap-dev` package).
- Run `sudo apt-get install libcap-dev` to install it.

### Installation

Run `make install` & `sudo make install`.

## Usage

To run tcpsnitch with curl and defaults options: `sudo tcpsnitch curl google.com`. 

To see verbose output and choose the log directory: `sudo tcpsnitch -v 4 -d /path curl google.com`.

See `tcpsnitch -h` for more information about the options.

## How it works?
