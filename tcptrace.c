#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <dlfcn.h>
#include <string.h>
#include <poll.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netdb.h>
#include <linux/tcp.h>
#include "lib.h"

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

typedef int (*orig_socket_type)(int __domain, int __type, int __protocol);

int socket (int __domain, int __type, int __protocol)
{
	orig_socket_type orig_socket;
	orig_socket = (orig_socket_type) dlsym(RTLD_NEXT, "socket");
	int fd = orig_socket(__domain, __type, __protocol);
	
	int domain_buf_size=MEMBER_SIZE(IntStrPair, str);
	char domain_buf[domain_buf_size];
	static const IntStrPair domain_map[] = {
		{ AF_INET, 	"AF_INET" },
		{ AF_INET6, 	"AF_INET6" },
		{ AF_UNIX, 	"AF_UNIX" }
	};

	if (!string_from_cons(__domain, domain_buf, domain_buf_size,
				domain_map, 
				sizeof(domain_map)/sizeof(IntStrPair))) {
		DEBUG(WARN, "Unknown socket domain: %d", __domain);
	}

	int type_buf_size=MEMBER_SIZE(IntStrPair, str);
	char type_buf[type_buf_size];
	static const IntStrPair type_map[] = {
		{ SOCK_STREAM, 	"SOCK_STREAM" },
		{ SOCK_DGRAM, 	"SOCK_DGRAM"  }
	};

	if (!string_from_cons(__type, type_buf, type_buf_size, type_map, 
			sizeof(type_map)/sizeof(IntStrPair))) {
		DEBUG(WARN, "Unknown socket type: %d", __type);	
	}

	DEBUG(INFO, "socket() created with fd %d (domain %s & type %s)", fd,
			domain_buf, type_buf);
	return fd;
}

/* Open a connection on socket FD to peer at ADDR (which LEN bytes long).
   For connectionless socket types, just set the default address to send to
   and the only address from which to accept transmissions.
   Return 0 on success, -1 for errors. */

typedef int (*orig_connect_type)(int __fd, __CONST_SOCKADDR_ARG __addr,
		socklen_t __len);

int connect (int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len)
{
	orig_connect_type orig_connect;
	orig_connect = (orig_connect_type) dlsym(RTLD_NEXT, "connect");
	DEBUG(INFO, "connect() on socket %d", __fd);
	return orig_connect(__fd, __addr, __len);
}

/* Shut down all or part of the connection open on socket FD.
   HOW determines what to shut down:
     SHUT_RD   = No more receptions;
     SHUT_WR   = No more transmissions;
     SHUT_RDWR = No more receptions or transmissions.
   Returns 0 on success, -1 for errors.  */

typedef int (*orig_shutdown_type)(int __fd, int __how);

int shutdown (int __fd, int __how)
{
	orig_shutdown_type orig_shutdown;
	orig_shutdown = (orig_shutdown_type) dlsym(RTLD_NEXT, "shutdown");
	DEBUG(INFO, "socket shutdown() with fd %d & how %d ", __fd, __how);
	return orig_shutdown(__fd, __how);
}

/* Prepare to accept connections on socket FD.
   N connection requests will be queued before further requests are refused.
   Returns 0 on success, -1 for errors.  */

typedef int (*orig_listen_type)(int __fd, int __n);

int listen (int __fd, int __n)
{
	orig_listen_type orig_listen;
	orig_listen = (orig_listen_type) dlsym(RTLD_NEXT, "listen");
	DEBUG(INFO, "listen() on socket %d", __fd);
	return orig_listen(__fd, __n);
}

/* Put the current value for socket FD's option OPTNAME at protocol level LEVEL
   into OPTVAL (which is *OPTLEN bytes long), and set *OPTLEN to the value's
   actual length.  Returns 0 on success, -1 for errors.  */

typedef int (*orig_getsockopt_type)(int __fd, int __level, int __optname,
		       void *__optval, socklen_t *__optlen);

int getsockopt (int __fd, int __level, int __optname, void *__optval,
		socklen_t *__optlen)
{
	orig_getsockopt_type orig_getsockopt;
	orig_getsockopt = (orig_getsockopt_type) dlsym(RTLD_NEXT, "getsockopt");
	DEBUG(INFO, "getsockopt() on socket %d", __fd);
	return orig_getsockopt(__fd, __level, __optname, __optval, __optlen);
}


/* Set socket FD's option OPTNAME at protocol level LEVEL
   to *OPTVAL (which is OPTLEN bytes long).
   Returns 0 on success, -1 for errors.  */
typedef int (*orig_setsockopt_type)(int __fd, int __level, int __optname,
		       const void *__optval, socklen_t __optlen);

int setsockopt (int __fd, int __level, int __optname, const void *__optval,
		socklen_t __optlen)
{
	orig_setsockopt_type orig_setsockopt;
	orig_setsockopt = (orig_setsockopt_type) dlsym(RTLD_NEXT, "setsockopt");

	struct protoent *protocole = getprotobynumber(__level);

	int optname_buf_size=MEMBER_SIZE(IntStrPair, str);
	char optname_buf[optname_buf_size];
	static const IntStrPair optname_map[] = {
		// Socket-level options
		{ SO_DEBUG,  	"SO_DEBUG" },
		{ SO_BROADCAST, "SO_BROADCAST" },
		{ SO_REUSEADDR,	"SO_REUSEADDR" },
		{ SO_KEEPALIVE, "SO_KEEPALIVE" },
		{ SO_LINGER,	"SO_KEEPALIVE" },
		{ SO_OOBINLINE, "SO_OOBINLINE" },
		{ SO_SNDBUF,	"SO_SNDBUF" },
		{ SO_RCVBUF,	"SO_RCVBUF" },
		{ SO_DONTROUTE,	"SO_DONTROUTE" },
		{ SO_RCVLOWAT,	"SO_RCVLOWAT" },
		{ SO_RCVTIMEO, 	"SO_RCVTIMEO" },
		{ SO_SNDLOWAT,	"SO_SNDLOWAT" },
		{ SO_SNDTIMEO,	"SO_SNDTIMEO" },
		// TCP-level options
		{ TCP_NODELAY,  	"TCP_NODELAY" },
		{ TCP_MAXSEG,		"TCP_MAXSEG" }, 
		{ TCP_CORK, 		"TCP_CORK" },
		{ TCP_KEEPIDLE, 	"TCP_KEEPIDLE" },
		{ TCP_KEEPINTVL, 	"TCP_KEEPINTVL" },
		{ TCP_KEEPCNT,		"TCP_KEEPCNT" },
		{ TCP_SYNCNT, 		"TCP_SYNCNT" },
		{ TCP_LINGER2, 		"TCP_LINGER2" },
		{ TCP_DEFER_ACCEPT, 	"TCP_DEFER_ACCEPT" },
		{ TCP_WINDOW_CLAMP, 	"TCP_WINDOW_CLAMP" },
		{ TCP_INFO,		"TCP_INFO" },
		{ TCP_QUICKACK,		"TCP_QUICKACK" },
		{ TCP_CONGESTION,	"TCP_CONGESTION" },
		{ TCP_MD5SIG,		"TCP_MD5SIG" },
		{ TCP_THIN_LINEAR_TIMEOUTS, "TCP_THIN_LINEAR_TIMEOUTS" },
		{ TCP_THIN_DUPACK,     	"TCP_THIN_DUPACK" },
		{ TCP_USER_TIMEOUT,	"TCP_USER_TIMEOUT" },
		{ TCP_REPAIR,		"TCP_REPAIR" },
		{ TCP_REPAIR_QUEUE, 	"TCP_REPAIR_QUEUE" },
		{ TCP_QUEUE_SEQ, 	"TCP_QUEUE_SEQ" },
		{ TCP_REPAIR_OPTIONS,	"TCP_REPAIR_OPTIONS" },
		{ TCP_FASTOPEN, 	"TCP_FASTOPEN" },
		{ TCP_TIMESTAMP,	"TCP_TIMESTAMP" },
		{ TCP_NOTSENT_LOWAT,	"TCP_NOTSENT_LOWAT" }
	};

	if (!string_from_cons(__optname, optname_buf, optname_buf_size,
			optname_map, sizeof(optname_map)/sizeof(IntStrPair))) {
		DEBUG(WARN, "Unknown setsockopt optname: %d", __optname);	
	}

	DEBUG(INFO, "setsockopt() on socket %d (level %s, optname %s)", __fd,
			protocole->p_name, optname_buf);

	return orig_setsockopt(__fd, __level, __optname, __optval, __optlen);
}

/* Send N bytes of BUF to socket FD.  Returns the number sent or -1. */

typedef ssize_t (*orig_send_type)(int __fd, const void *__buf, size_t __n, 
		int __flags);

ssize_t send (int __fd, const void *__buf, size_t __n, int __flags)
{
	DEBUG(INFO, "send() on socket %d", __fd);
	orig_send_type orig_send;
	orig_send = (orig_send_type) dlsym(RTLD_NEXT, "send");
	return orig_send(__fd, __buf, __n, __flags);
}

/* Read N bytes into BUF from socket FD.
   Returns the number read or -1 for errors. */

typedef ssize_t (*orig_recv_type)(int __fd, void *__buf, size_t __n,
		int __flags);

ssize_t recv (int __fd, void *__buf, size_t __n, int __flags)
{	
	DEBUG(INFO, "recv() on socket %d", __fd);
	orig_recv_type orig_recv;
	orig_recv = (orig_recv_type) dlsym(RTLD_NEXT, "recv");
	return orig_recv(__fd, __buf, __n, __flags);
}

/* Send N bytes of BUF on socket FD to peer at address ADDR (which is
   ADDR_LEN bytes long).  Returns the number sent, or -1 for errors. */

typedef ssize_t (*orig_sendto_type)(int __fd, const void *__buf, size_t __n, 
		int __flags, __CONST_SOCKADDR_ARG __addr, 
		socklen_t __addr_len);

ssize_t sendto (int __fd, const void *__buf, size_t __n, int __flags, 
		__CONST_SOCKADDR_ARG __addr, socklen_t __addr_len)
{
	DEBUG(INFO, "sendto() on socket %d", __fd);
	orig_sendto_type orig_sendto;
	orig_sendto = (orig_sendto_type) dlsym(RTLD_NEXT, "sendto");
	return orig_sendto(__fd, __buf, __n, __flags, __addr, __addr_len);
}

/* Read N bytes into BUF through socket FD.
   If ADDR is not NULL, fill in *ADDR_LEN bytes of it with tha address of
   the sender, and store the actual size of the address in *ADDR_LEN.
   Returns the number of bytes read or -1 for errors. */

typedef ssize_t (*orig_recvfrom_type)(int __fd, void *__restrict __buf, 
		size_t __n, int __flags, __SOCKADDR_ARG __addr,
		socklen_t *__restrict __addr_len);

ssize_t recvfrom (int __fd, void *__restrict __buf, size_t __n,
			 int __flags, __SOCKADDR_ARG __addr,
			 socklen_t *__restrict __addr_len) 
{
	DEBUG(INFO, "recvfrom() on socket %d", __fd);
	orig_recvfrom_type orig_recvfrom;
	orig_recvfrom = (orig_recvfrom_type) dlsym(RTLD_NEXT, "recvfrom");
	return orig_recvfrom(__fd, __buf, __n, __flags, __addr, __addr_len);
}

/* Send a message described MESSAGE on socket FD.
   Returns the number of bytes sent, or -1 for errors. */

typedef ssize_t (*orig_sendmsg_type)(int __fd, const struct msghdr *__message, 
		int __flags);

ssize_t sendmsg (int __fd, const struct msghdr *__message, int __flags) 
{
	DEBUG(INFO, "sendmsg() on socket %d", __fd);
	orig_sendmsg_type orig_sendmsg;
	orig_sendmsg = (orig_sendmsg_type) dlsym(RTLD_NEXT, "sendmsg");
	return orig_sendmsg(__fd, __message, __flags); 
}

/* Receive a message as described by MESSAGE from socket FD.
   Returns the number of bytes read or -1 for errors. */

typedef ssize_t (*orig_recvmsg_type)(int __fd, struct msghdr *__message, 
		int __flags);

ssize_t recvmsg (int __fd, struct msghdr *__message, int __flags)
{
	DEBUG(INFO, "recvmsg() on socket %d", __fd);
	orig_recvmsg_type orig_recvmsg;
	orig_recvmsg = (orig_recvmsg_type) dlsym(RTLD_NEXT, "recvmsg");
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
  
int close (int __fd)
{
	orig_close_type orig_close;
	orig_close = (orig_close_type) dlsym(RTLD_NEXT, "close");
	
	if (is_socket(__fd)) {
		DEBUG(INFO, "close() on socket %d", __fd);
	}

	return orig_close(__fd);
}

/* Write N bytes of BUF to FD.  Return the number written, or -1. */

typedef ssize_t (*orig_write_type)(int __fd, const void *__buf, size_t __n);

ssize_t write (int __fd, const void *__buf, size_t __n)
{	
	orig_write_type orig_write;
	orig_write = (orig_write_type) dlsym(RTLD_NEXT, "write");

	if (is_socket(__fd)) {
		DEBUG(INFO, "write() on socket %d", __fd);
	}

	return orig_write(__fd, __buf, __n); 
}

/* Read NBYTES into BUF from FD.  Return the
   number read, -1 for errors or 0 for EOF. */

typedef ssize_t (*orig_read_type)(int __fd, void *__buf, size_t __nbytes);

ssize_t read (int __fd, void *__buf, size_t __nbytes)
{	
	orig_read_type orig_read;
	orig_read = (orig_read_type) dlsym(RTLD_NEXT, "read");

	if (is_socket(__fd)) {
		DEBUG(INFO, "read() on socket %d", __fd);
	}

	return orig_read(__fd, __buf, __nbytes); 
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
	
ssize_t writev (int __fd, const struct iovec *__iovec, int __count)
{
	orig_writev_type orig_writev;
	orig_writev = (orig_writev_type) dlsym(RTLD_NEXT, "writev");

	if (is_socket(__fd)) {
		DEBUG(INFO, "writev() on socket %d", __fd);
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

ssize_t readv (int __fd, const struct iovec *__iovec, int __count)
{	
	orig_readv_type orig_readv;
	orig_readv = (orig_readv_type) dlsym(RTLD_NEXT, "readv");

	if (is_socket(__fd)) {
		DEBUG(INFO, "readv() on socket %d", __fd);
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

ssize_t sendfile (int __out_fd, int __in_fd, off_t *__offset, size_t __count)
{
	orig_sendfile_type orig_sendfile;
	orig_sendfile = (orig_sendfile_type) dlsym(RTLD_NEXT, "sendfile");
	
	if (is_socket(__out_fd)) {
		DEBUG(INFO, "sendfile() on socket %d", __out_fd);
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

int poll (struct pollfd *__fds, nfds_t __nfds, int __timeout)
{
	orig_poll_type orig_poll;
	orig_poll = (orig_poll_type) dlsym(RTLD_NEXT, "poll");

	unsigned long ndfs = __nfds;
	int i;
	for (i=0; (unsigned long)i < ndfs; i++) {
		if (is_socket(__fds[i].fd)) {
			DEBUG(INFO, "poll() on socket %d", __fds[i].fd);	
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
