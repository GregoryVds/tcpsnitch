# Tcpsnitch

WORK IN PROGRESS, (MOST PROBABLY) NOT READY FOR USE!

## Overview

Tcpsnitch is a program that helps investigate the interactions between an application, the TCP stack and the network. It runs the specified command until it exits and records useful information for each TCP connection:
- The system calls made along with their arguments and return value.
- The value of the TCP\_INFO socket option at user-defined intervals to provide information about the state of a TCP connection in the kernel.
- A pcap trace of all the packets sent/received.
- Aggregate information about the TCP connection such as the number of syscalls made or bytes sent/received.

## Intallation

Dependencies:
- jansson library (https://jansson.readthedocs.io)
- pcap library (http://www.tcpdump.org/)

## Usage


## How it works?
