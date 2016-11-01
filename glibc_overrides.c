/*
 * Author: Gregory Vander Schueren
 * Email: gregory.vanderschueren@gmail.com
 * Date: October, 2016
 */

/*
 * This file contains all (and the only) symbols that should be exposed by
 * the NETSPY library. Those symbols are most of the networking related
 * functions from the C standard librairies.
 *
 * NETSPY works by intercepting all calls to theses functions and by performing
 * custom processing before and/or after calling the real implementation. This
 * will prove valuable when trying the model the network behaviour of
 * applications.
 *
 * On Linux, NETSPY works using LD_PRELOAD. This environnement variable tells
 * the linker to automatically link librairies in LD_PRELOAD BEFORE any other
 * dynamic librairy. When multiple librairies which define the same symbol are
 * linked, the first one to be linked gets the precedence. This way, we can
 * effectively override any function from the C standard library. We then use
 * the dynamic linking library <dlfcn.h> to get a reference to the original
 * implementation and call it.
 *
 * NETPSY has currently only been tested on Linux with the glibc implementation
 * of the C standard librairies. We mainly override Posix functions, but also
 * some Linux specific functions such sendfile().
 *
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <dlfcn.h>
#include <string.h>
#include <poll.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <errno.h>
#include "lib.h"
#include "tcp_spy.h"
#include "string_helpers.h"
#include "logger.h"

/*
 Use "standard" font of http://patorjk.com/software/taag to generate ASCII arts
*/

/*
  ____   ___   ____ _  _______ _____      _    ____ ___
 / ___| / _ \ / ___| |/ / ____|_   _|    / \  |  _ \_ _|
 \___ \| | | | |   | ' /|  _|   | |     / _ \ | |_) | |
  ___) | |_| | |___| . \| |___  | |    / ___ \|  __/| |
 |____/ \___/ \____|_|\_\_____| |_|   /_/   \_\_|  |___|

 sys/socket.h - Internet Protocol family

 functions: socket(), connect(), shutdown(), listen(), getsockopt(),
 setsockopt(), send(), sendto(), sendmsg(), recv(), recvfrom(), recvmsg().

*/

/* Create a new socket of type TYPE in domain DOMAIN, using
   protocol PROTOCOL.  If PROTOCOL is zero, one is chosen automatically.
   Returns a file descriptor for the new socket, or -1 for errors.  */

#define SOCK_TYPE_MASK 0b1111

typedef int (*orig_socket_type)(int __domain, int __type, int __protocol);

int socket(int __domain, int __type, int __protocol) {
	orig_socket_type orig_socket;
	orig_socket = (orig_socket_type)dlsym(RTLD_NEXT, "socket");

	/* Translate domain to str */
	char *domain = alloc_sock_domain_str(__domain);
	LOG(INFO, "socket() called (domain %s)", domain);
	free(domain);

	/* Inspect flag parameters */
	bool sock_cloexec = __type & SOCK_CLOEXEC;
	bool sock_nonblock = __type & SOCK_NONBLOCK;

	/* Perform syscall */
	int fd = orig_socket(__domain, __type, __protocol);
	if (is_tcp_socket(fd)) {
		LOG(INFO, "socket %d is TCP", fd);
		tcp_sock_opened(fd, __domain, __protocol, sock_cloexec,
				sock_nonblock);
		tcp_info_dump(fd);
	}

	return fd;
}

/* Open a connection on socket FD to peer at ADDR (which LEN bytes long).
   For connectionless socket types, just set the default address to send to
   and the only address from which to accept transmissions.
   Return 0 on success, -1 for errors. */

typedef int (*orig_connect_type)(int __fd, const struct sockaddr *__addr,
				 socklen_t __len);

int connect(int __fd, const struct sockaddr *__addr, socklen_t __len) {
	orig_connect_type orig_connect;
	orig_connect = (orig_connect_type)dlsym(RTLD_NEXT, "connect");
	LOG(INFO, "connect() called on socket %d.", __fd);

	/* Perform syscall */
	if (is_tcp_socket(__fd)) tcp_start_capture(__fd, __addr);
	int ret = orig_connect(__fd, __addr, __len);
	int err = errno;

	if (is_tcp_socket(__fd)) {
		tcp_connect(__fd, ret, err, __addr, __len);
		tcp_info_dump(__fd);
	}

	return ret;
}

/* Shut down all or part of the connection open on socket FD.
   HOW determines what to shut down:
     SHUT_RD   = No more receptions;
     SHUT_WR   = No more transmissions;
     SHUT_RDWR = No more receptions and transmissions;
   Returns 0 on success, -1 for errors.  */

typedef int (*orig_shutdown_type)(int __fd, int __how);

int shutdown(int __fd, int __how) {
	orig_shutdown_type orig_shutdown;
	orig_shutdown = (orig_shutdown_type)dlsym(RTLD_NEXT, "shutdown");
	LOG(INFO, "shutdown() called on socket %d.", __fd);

	if (is_tcp_socket(__fd)) tcp_info_dump(__fd);
	/* Perform syscall */
	int ret = orig_shutdown(__fd, __how);
	int err = errno;

	if (is_tcp_socket(__fd)) {
		tcp_shutdown(__fd, ret, err, __how);
		tcp_info_dump(__fd);
	}

	return ret;
}

/* Prepare to accept connections on socket FD.
   N connection requests will be queued before further requests are refused.
   Returns 0 on success, -1 for errors.  */

typedef int (*orig_listen_type)(int __fd, int __n);

int listen(int __fd, int __n) {
	orig_listen_type orig_listen;
	orig_listen = (orig_listen_type)dlsym(RTLD_NEXT, "listen");
	LOG(INFO, "listen() called on socket %d.", __fd);

	/* Perform syscall */
	int ret = orig_listen(__fd, __n);
	int err = errno;

	if (is_tcp_socket(__fd)) {
		tcp_listen(__fd, ret, err, __n);
		tcp_info_dump(__fd);
	}

	return ret;
}

/* Set socket FD's option OPTNAME at protocol level LEVEL
   to *OPTVAL (which is OPTLEN bytes long).
   Returns 0 on success, -1 for errors.  */
typedef int (*orig_setsockopt_type)(int __fd, int __level, int __optname,
				    const void *__optval, socklen_t __optlen);

int setsockopt(int __fd, int __level, int __optname, const void *__optval,
	       socklen_t __optlen) {
	orig_setsockopt_type orig_setsockopt;
	orig_setsockopt = (orig_setsockopt_type)dlsym(RTLD_NEXT, "setsockopt");
	LOG(INFO, "setsockopt() called on socket %d.", __fd);

	/* Perform syscall */
	int ret = orig_setsockopt(__fd, __level, __optname, __optval, __optlen);
	int err = errno;

	if (is_tcp_socket(__fd)) {
		tcp_setsockopt(__fd, ret, err, __level, __optname);
		tcp_info_dump(__fd);
	}

	return ret;
}

/* Send N bytes of BUF to socket FD.  Returns the number sent or -1. */

typedef ssize_t (*orig_send_type)(int __fd, const void *__buf, size_t __n,
				  int __flags);

ssize_t send(int __fd, const void *__buf, size_t __n, int __flags) {
	orig_send_type orig_send;
	orig_send = (orig_send_type)dlsym(RTLD_NEXT, "send");
	LOG(INFO, "send() called on socket %d.", __fd);

	if (is_tcp_socket(__fd)) tcp_info_dump(__fd);
	/* Perform syscall */
	ssize_t ret = orig_send(__fd, __buf, __n, __flags);
	int err = errno;

	if (is_tcp_socket(__fd)) {
		tcp_data_sent(__fd, ret, err, __n);
		tcp_info_dump(__fd);
	}

	return ret;
}

/* Read N bytes into BUF from socket FD.
   Returns the number read or -1 for errors. */

typedef ssize_t (*orig_recv_type)(int __fd, void *__buf, size_t __n,
				  int __flags);

ssize_t recv(int __fd, void *__buf, size_t __n, int __flags) {
	orig_recv_type orig_recv;
	orig_recv = (orig_recv_type)dlsym(RTLD_NEXT, "recv");
	LOG(INFO, "recv() called on socket %d.", __fd);

	if (is_tcp_socket(__fd)) tcp_info_dump(__fd);
	/* Perform syscall */
	ssize_t ret = orig_recv(__fd, __buf, __n, __flags);
	int err = errno;

	if (is_tcp_socket(__fd)) {
		tcp_data_received(__fd, ret, err, __n);
		tcp_info_dump(__fd);
	}

	return ret;
}

/* Send N bytes of BUF on socket FD to peer at address ADDR (which is
   ADDR_LEN bytes long).  Returns the number sent, or -1 for errors. */

typedef ssize_t (*orig_sendto_type)(int __fd, const void *__buf, size_t __n,
				    int __flags, const struct sockaddr *__addr,
				    socklen_t __addr_len);

ssize_t sendto(int __fd, const void *__buf, size_t __n, int __flags,
	       const struct sockaddr *__addr, socklen_t __addr_len) {
	orig_sendto_type orig_sendto;
	orig_sendto = (orig_sendto_type)dlsym(RTLD_NEXT, "sendto");

	/* Extract IP address to human readable string */
	char *addr_str = alloc_addr_str(__addr);
	LOG(INFO, "sendto() on socket %d (%zu bytes to %s)", __fd, __n,
	      addr_str);
	free(addr_str);

	if (is_tcp_socket(__fd)) tcp_info_dump(__fd);
	/* Perform syscall */
	ssize_t ret =
	    orig_sendto(__fd, __buf, __n, __flags, __addr, __addr_len);
	int err = errno;

	if (is_tcp_socket(__fd)) {
		tcp_data_sent(__fd, ret, err, __n);
		tcp_info_dump(__fd);
	}

	return ret;
}

/* Read N bytes into BUF through socket FD.
   If ADDR is not NULL, fill in *ADDR_LEN bytes of it with tha address of
   the sender, and store the actual size of the address in *ADDR_LEN.
   Returns the number of bytes read or -1 for errors. */

typedef ssize_t (*orig_recvfrom_type)(int __fd, void *__restrict __buf,
				      size_t __n, int __flags,
				      struct sockaddr *__addr,
				      socklen_t *__restrict __addr_len);

ssize_t recvfrom(int __fd, void *__restrict __buf, size_t __n, int __flags,
		 struct sockaddr *__addr, socklen_t *__restrict __addr_len) {
	orig_recvfrom_type orig_recvfrom;
	orig_recvfrom = (orig_recvfrom_type)dlsym(RTLD_NEXT, "recvfrom");
	LOG(INFO, "recvfrom() called.");

	if (is_tcp_socket(__fd)) tcp_info_dump(__fd);
	/* Perform syscall */
	ssize_t ret =
	    orig_recvfrom(__fd, __buf, __n, __flags, __addr, __addr_len);
	int err = errno;

	if (is_tcp_socket(__fd)) {
		tcp_data_received(__fd, ret, err, __n);
		tcp_info_dump(__fd);
	}

	/* Extract IP address to human readable string */
	char *addr_str = alloc_addr_str(__addr);
	LOG(INFO, "recvfrom() on socket %d (%zu bytes from %s)", __fd, __n,
	      addr_str);
	free(addr_str);

	return ret;
}

/* Send a message described MESSAGE on socket FD.
   Returns the number of bytes sent, or -1 for errors. */

typedef ssize_t (*orig_sendmsg_type)(int __fd, const struct msghdr *__message,
				     int __flags);

ssize_t sendmsg(int __fd, const struct msghdr *__message, int __flags) {
	LOG(WARN, "NOT IMPLEMENTED: sendmsg() on socket %d", __fd);
	orig_sendmsg_type orig_sendmsg;
	orig_sendmsg = (orig_sendmsg_type)dlsym(RTLD_NEXT, "sendmsg");
	return orig_sendmsg(__fd, __message, __flags);
}

/* Receive a message as described by MESSAGE from socket FD.
   Returns the number of bytes read or -1 for errors. */

typedef ssize_t (*orig_recvmsg_type)(int __fd, struct msghdr *__message,
				     int __flags);

ssize_t recvmsg(int __fd, struct msghdr *__message, int __flags) {
	LOG(WARN, "NOT IMPLEMENTED: recvmsg() on socket %d", __fd);
	orig_recvmsg_type orig_recvmsg;
	orig_recvmsg = (orig_recvmsg_type)dlsym(RTLD_NEXT, "recvmsg");
	return orig_recvmsg(__fd, __message, __flags);
}

/*
  _   _ _   _ ___ ____ _____ ____       _    ____ ___
 | | | | \ | |_ _/ ___|_   _|  _ \     / \  |  _ \_ _|
 | | | |  \| || |\___ \ | | | | | |   / _ \ | |_) | |
 | |_| | |\  || | ___) || | | |_| |  / ___ \|  __/| |
  \___/|_| \_|___|____/ |_| |____/  /_/   \_\_|  |___|

 unistd.h - standard symbolic constants and types

 functions: close(), write(), read().

*/

/* Close the file descriptor FD. */

typedef int (*orig_close_type)(int __fd);

int close(int __fd) {
	orig_close_type orig_close;
	orig_close = (orig_close_type)dlsym(RTLD_NEXT, "close");

	LOG(INFO, "close() on socket %d", __fd);

	bool is_tcp = is_tcp_socket(__fd);
	if (is_tcp) tcp_info_dump(__fd);
	/* Perform syscall */
	int ret = orig_close(__fd);
	int err = errno;

	if (is_tcp) tcp_sock_closed(__fd, ret, err, true);

	return ret;
}

/* Write N bytes of BUF to FD.  Return the number written, or -1. */

typedef ssize_t (*orig_write_type)(int __fd, const void *__buf, size_t __n);

ssize_t write(int __fd, const void *__buf, size_t __n) {
	orig_write_type orig_write;
	orig_write = (orig_write_type)dlsym(RTLD_NEXT, "write");
	if (is_inet_socket(__fd)) LOG(INFO, "write() on socket %d", __fd);

	if (is_tcp_socket(__fd)) tcp_info_dump(__fd);
	/* Perform syscall */
	int ret = orig_write(__fd, __buf, __n);
	int err = errno;

	if (is_tcp_socket(__fd)) {
		tcp_data_sent(__fd, ret, err, __n);
		tcp_info_dump(__fd);
	}

	return ret;
}

/* Read NBYTES into BUF from FD.  Return the
   number read, -1 for errors or 0 for EOF. */

typedef ssize_t (*orig_read_type)(int __fd, void *__buf, size_t __nbytes);

ssize_t read(int __fd, void *__buf, size_t __nbytes) {
	orig_read_type orig_read;
	orig_read = (orig_read_type)dlsym(RTLD_NEXT, "read");
	if (is_inet_socket(__fd)) LOG(INFO, "read() on socket %d", __fd);

	if (is_tcp_socket(__fd)) tcp_info_dump(__fd);
	/* Perform syscall */
	int ret = orig_read(__fd, __buf, __nbytes);
	int err = errno;

	if (is_tcp_socket(__fd)) {
		tcp_data_received(__fd, ret, err, __nbytes);
		tcp_info_dump(__fd);
	}

	return ret;
}

/*
  _   _ ___ ___       _    ____ ___
 | | | |_ _/ _ \     / \  |  _ \_ _|
 | | | || | | | |   / _ \ | |_) | |
 | |_| || | |_| |  / ___ \|  __/| |
  \___/|___\___/  /_/   \_\_|  |___|

 sys/uio.h - definitions for vector I/O operations

 functions: writev(), readv()

*/

/* Write data pointed by the buffers described by IOVEC, which
   is a vector of COUNT 'struct iovec's, to file descriptor FD.
   The data is written in the order specified.
   Operates just like 'write' (see <unistd.h>) except that the data
   are taken from IOVEC instead of a contiguous buffer. */

typedef ssize_t (*orig_writev_type)(int __fd, const struct iovec *__iovec,
				    int __count);

ssize_t writev(int __fd, const struct iovec *__iovec, int __count) {
	orig_writev_type orig_writev;
	orig_writev = (orig_writev_type)dlsym(RTLD_NEXT, "writev");

	if (is_inet_socket(__fd)) {
		LOG(WARN, "NOT IMPLEMENTED: writev() on socket %d", __fd);
	}

	return orig_writev(__fd, __iovec, __count);
}

/* Read data from file descriptor FD, and put the result in the
   buffers described by IOVEC, which is a vector of COUNT 'struct iovec's.
   The buffers are filled in the order specified.
   Operates just like 'read' (see <unistd.h>) except that data are
   put in IOVEC instead of a contiguous buffer. */

typedef ssize_t (*orig_readv_type)(int __fd, const struct iovec *__iovec,
				   int __count);

ssize_t readv(int __fd, const struct iovec *__iovec, int __count) {
	orig_readv_type orig_readv;
	orig_readv = (orig_readv_type)dlsym(RTLD_NEXT, "readv");

	if (is_inet_socket(__fd)) {
		LOG(WARN, "NOT IMPLEMENTED: readv() on socket %d", __fd);
	}

	return orig_readv(__fd, __iovec, __count);
}

/*
  ____  _____ _   _ ____  _____ ___ _     _____      _    ____ ___
 / ___|| ____| \ | |  _ \|  ___|_ _| |   | ____|    / \  |  _ \_ _|
 \___ \|  _| |  \| | | | | |_   | || |   |  _|     / _ \ | |_) | |
  ___) | |___| |\  | |_| |  _|  | || |___| |___   / ___ \|  __/| |
 |____/|_____|_| \_|____/|_|   |___|_____|_____| /_/   \_\_|  |___|

 sendfile - transfer data between file descriptors

 functions: sendfile()
*/

/* Send up to COUNT bytes from file associated with IN_FD starting at
   *OFFSET to descriptor OUT_FD.  Set *OFFSET to the IN_FD's file position
   following the read bytes.  If OFFSET is a null pointer, use the normal
   file position instead.  Return the number of written bytes, or -1 in
   case of error.  */

typedef ssize_t (*orig_sendfile_type)(int __out_fd, int __in_fd,
				      off_t *__offset, size_t __count);

ssize_t sendfile(int __out_fd, int __in_fd, off_t *__offset, size_t __count) {
	orig_sendfile_type orig_sendfile;
	orig_sendfile = (orig_sendfile_type)dlsym(RTLD_NEXT, "sendfile");

	if (is_inet_socket(__out_fd)) {
		LOG(WARN, "NOT IMPLEMENTED: sendfile() on socket %d",
		      __out_fd);
	}

	return orig_sendfile(__out_fd, __in_fd, __offset, __count);
}

/*
  ____   ___  _     _          _    ____ ___
 |  _ \ / _ \| |   | |        / \  |  _ \_ _|
 | |_) | | | | |   | |       / _ \ | |_) | |
 |  __/| |_| | |___| |___   / ___ \|  __/| |
 |_|    \___/|_____|_____| /_/   \_\_|  |___|

 poll.h - definitions for the poll() function

 functions: poll()
*/

/* Poll the file descriptors described by the NFDS structures starting at
   FDS.  If TIMEOUT is nonzero and not -1, allow TIMEOUT milliseconds for
   an event to occur; if TIMEOUT is -1, block until an event occurs.
   Returns the number of file descriptors with events, zero if timed out,
   or -1 for errors.*/

typedef int (*orig_poll_type)(struct pollfd *__fds, nfds_t __nfds,
			      int __timeout);

int poll(struct pollfd *__fds, nfds_t __nfds, int __timeout) {
	orig_poll_type orig_poll;
	orig_poll = (orig_poll_type)dlsym(RTLD_NEXT, "poll");

	unsigned long ndfs = __nfds;
	int i;
	for (i = 0; (unsigned long)i < ndfs; i++) {
		struct pollfd *pollfd = __fds + i;

		if (is_inet_socket(pollfd->fd)) {
			short events = pollfd->events;
			char flags[100] = "events:";
			if (events & POLLIN) strcat(flags, " POLLIN");
			if (events & POLLPRI) strcat(flags, " POLLPRI");
			if (events & POLLOUT) strcat(flags, " POLLOUT");
			if (events & POLLRDHUP) strcat(flags, " POLLRDHUP");
			if (events & POLLERR) strcat(flags, " POLLERR");
			if (events & POLLHUP) strcat(flags, " POLLHUP");
			if (events & POLLNVAL) strcat(flags, " POLLNVAL");

			LOG(INFO, "poll() on socket %d (%s)", pollfd->fd,
			      flags);
		}
	}

	return orig_poll(__fds, __nfds, __timeout);
}

/*
  ____  _____ _     _____ ____ _____      _    ____ ___
 / ___|| ____| |   | ____/ ___|_   _|    / \  |  _ \_ _|
 \___ \|  _| | |   |  _|| |     | |     / _ \ | |_) | |
  ___) | |___| |___| |__| |___  | |    / ___ \|  __/| |
 |____/|_____|_____|_____\____| |_|   /_/   \_\_|  |___|

 sys/select.h - select types

 functions: select()
*/

/* Check the first NFDS descriptors each in READFDS (if not NULL) for read
   readiness, in WRITEFDS (if not NULL) for write readiness, and in EXCEPTFDS
   (if not NULL) for exceptional conditions.  If TIMEOUT is not NULL, time out
   after waiting the interval specified therein.  Returns the number of ready
   descriptors, or -1 for errors.*/

/*
typedef int (*orig_select_type)(int __nfds, fd_set *__readfds,
		fd_set *__writefds, fd_set *__exceptfds,
		struct timeval *__timeout);

int select (int __nfds, fd_set *__restrict __readfds,
		   fd_set *__restrict __writefds,
		   fd_set *__restrict __exceptfds,
		   struct timeval *__restrict __timeout);
*/

/*
  _   _ _____ _____ ____  ____       _    ____ ___
 | \ | | ____|_   _|  _ \| __ )     / \  |  _ \_ _|
 |  \| |  _|   | | | | | |  _ \    / _ \ | |_) | |
 | |\  | |___  | | | |_| | |_) |  / ___ \|  __/| |
 |_| \_|_____| |_| |____/|____/  /_/   \_\_|  |___|

 netdb.h - definitions for network database operations

 functions: gethostbyaddr(), gethostbyname(), getaddrinfo(), getnameinfo().

 Note: the first 2 are obsolete and should not be used! It would be interesting
 to inspect how many programs still use them.
*/

/* Obsolete DNS functions */

/* Return entry from host data base which address match ADDR with
   length LEN and type TYPE.   */

typedef struct hostent *(*orig_gethostbyaddr_type)(const void *__addr,
						   __socklen_t __len,
						   int __type);

struct hostent *gethostbyaddr(const void *__addr, __socklen_t __len,
			      int __type) {
	orig_gethostbyaddr_type orig_gethostbyaddr;
	orig_gethostbyaddr =
	    (orig_gethostbyaddr_type)dlsym(RTLD_NEXT, "gethostbyaddr");
	LOG(INFO, "gethostbyaddr()");
	return orig_gethostbyaddr(__addr, __len, __type);
}

/* Return entry from host data base for host with NAME. */

typedef struct hostent *(*orig_gethostbyname_type)(const char *__name);

struct hostent *gethostbyname(const char *__name) {
	orig_gethostbyname_type orig_gethostbyname;
	orig_gethostbyname =
	    (orig_gethostbyname_type)dlsym(RTLD_NEXT, "gethostbyname");
	LOG(INFO, "gethostbyname() on %s", __name);
	return orig_gethostbyname(__name);
}

/* Translate name of a service location and/or a service name to set of
   socket addresses.*/

typedef int (*orig_getaddrinfo_type)(const char *__name, const char *__service,
				     const struct addrinfo *__req,
				     struct addrinfo **__pai);

int getaddrinfo(const char *__name, const char *__service,
		const struct addrinfo *__req, struct addrinfo **__pai) {
	orig_getaddrinfo_type orig_getaddrinfo;
	orig_getaddrinfo =
	    (orig_getaddrinfo_type)dlsym(RTLD_NEXT, "getaddrinfo");
	LOG(INFO, "getaddrinfo() for %s:%s", __name, __service);
	return orig_getaddrinfo(__name, __service, __req, __pai);
}

/* Translate a socket address to a location and service name.*/

typedef int (*orig_getnameinfo_type)(const struct sockaddr *__sa,
				     socklen_t __salen, char *__host,
				     socklen_t __hostlen, char *__serv,
				     socklen_t __servlen, int __flags);

int getnameinfo(const struct sockaddr *__sa, socklen_t __salen, char *__host,
		socklen_t __hostlen, char *__serv, socklen_t __servlen,
		int __flags) {
	orig_getnameinfo_type orig_getnameinfo;
	orig_getnameinfo =
	    (orig_getnameinfo_type)dlsym(RTLD_NEXT, "getnameinfo");
	LOG(INFO, "getnameinfo()");
	return orig_getnameinfo(__sa, __salen, __host, __hostlen, __serv,
				__servlen, __flags);
}
