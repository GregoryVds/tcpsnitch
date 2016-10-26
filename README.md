## netspy

First prototype aiming at basic gathering of TCP information on client applications using system calls interception with `LD_PRELOAD`.

For a given process, we want to:
- Record all TCP connections established.
- For each TCP connection, record all calls to send/recv (& equivalent functions).
- For each TCP connection, gather TCP infos using getsockopt() everytime our library is invoked.

# Intallation

## Shared libraries
- Requires jansson library (-ljansson)
- Requires dynamic linking library (-ldl)
- Requires poxix threads library (-lpthread)
- Requires pcap library (-lpcap)

In Linux, for example, pcap needs the `CAP_NET_RAW` capability to be available to the user. What about `CAP_NET_ADMIN`?




