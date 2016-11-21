## netspy

Shared library to intercept network related syscalls made via libc (using `LD_PRELOAD`) and analyse the TCP stack.
Syscalls for each TCP connection are recorded (along with the parameters) and save along a packet trace. At regular interval the state of TCP\_INFO is captured.

# Intallation

## Static librairies
- Requies slog library (-lslog), see https://github.com/kala13x/slog

## Shared librairies
- Requires jansson library (-ljansson)
- Requires dynamic linking library (-ldl)
- Requires poxix threads library (-lpthread)
- Requires pcap library (-lpcap)

In Linux, for example, pcap needs the `CAP_NET_RAW` capability to be available to the user. What about `CAP_NET_ADMIN`?

