## tcptrace

First prototype aiming at basic gathering of TCP information on client applications using system calls interception with LD_PRELOAD.

For a given process, we want to:
- Record all TCP connections established.
- For each TCP connection, record all calls to send/recv (& equivalent functions).
- For each TCP connection, gather TCP infos using getsockopt() everytime our library is invoked.
