#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <dlfcn.h>

/* Create a new socket of type TYPE in domain DOMAIN, using
   protocol PROTOCOL.  If PROTOCOL is zero, one is chosen automatically.
   Returns a file descriptor for the new socket, or -1 for errors.  */
typedef int (*orig_socket_type)(int __domain, int __type, int __protocol);

int socket (int __domain, int __type, int __protocol)
{
	fprintf(stderr, "socket() called!\n");
	orig_socket_type orig_socket;
	orig_socket = (orig_socket_type) dlsym(RTLD_NEXT, "socket");
	return orig_socket(__domain, __type, __protocol);
}

/*
  ____   ___   ____ _  _______ _____      _    ____ ___ 
 / ___| / _ \ / ___| |/ / ____|_   _|    / \  |  _ \_ _|
 \___ \| | | | |   | ' /|  _|   | |     / _ \ | |_) | | 
  ___) | |_| | |___| . \| |___  | |    / ___ \|  __/| | 
 |____/ \___/ \____|_|\_\_____| |_|   /_/   \_\_|  |___|

 Here we only consider the socket specific API: send(), sendto(), sendmsg() and
 recv(), recvfrom(), recvmsg().

 Defined in "sys/socket.h"
*/                                                               


/* Send N bytes of BUF to socket FD.  Returns the number sent or -1. */

typedef ssize_t (*orig_send_type)(int __fd, const void *__buf, size_t __n, 
		int __flags);

ssize_t send (int __fd, const void *__buf, size_t __n, int __flags)
{
	fprintf(stderr, "send() called!\n");
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
	fprintf(stderr, "recv() called!\n");
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
	fprintf(stderr, "sendto() called!\n");
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
	fprintf(stderr, "recvfrom() called!\n");
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
	fprintf(stderr, "sendmsg() called!\n");
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
	fprintf(stderr, "recvmsg() called!\n");
	orig_recvmsg_type orig_recvmsg;
	orig_recvmsg = (orig_recvmsg_type) dlsym(RTLD_NEXT, "recvmsg");
	return orig_recvmsg(__fd, __message, __flags); 
}


/*
  ____ _____  _    _   _ ____    _    ____  ____       _    ____ ___ 
 / ___|_   _|/ \  | \ | |  _ \  / \  |  _ \|  _ \     / \  |  _ \_ _|
 \___ \ | | / _ \ |  \| | | | |/ _ \ | |_) | | | |   / _ \ | |_) | | 
  ___) || |/ ___ \| |\  | |_| / ___ \|  _ <| |_| |  / ___ \|  __/| | 
 |____/ |_/_/   \_\_| \_|____/_/   \_\_| \_\____/  /_/   \_\_|  |___| 
	
 We also need to consider the standard I/O api that could be used to write or
 read to a socket: write(), read(), writev(), readv(), sendfile().

 Defined in "unistd.h", "sys/uio.h", "sys/sendfile.h". 
*/

/* Write N bytes of BUF to FD.  Return the number written, or -1. */

typedef ssize_t (*orig_write_type)(int __fd, const void *__buf, size_t __n);

ssize_t write (int __fd, const void *__buf, size_t __n)
{	
	fprintf(stderr, "write() called!\n");
	orig_write_type orig_write;
	orig_write = (orig_write_type) dlsym(RTLD_NEXT, "write");
	return orig_write(__fd, __buf, __n); 
}

/* Read NBYTES into BUF from FD.  Return the
   number read, -1 for errors or 0 for EOF. */

typedef ssize_t (*orig_read_type)(int __fd, void *__buf, size_t __nbytes);

ssize_t read (int __fd, void *__buf, size_t __nbytes)
{	
	fprintf(stderr, "read() called!\n");
	orig_read_type orig_read;
	orig_read = (orig_read_type) dlsym(RTLD_NEXT, "read");
	return orig_read(__fd, __buf, __nbytes); 
}

/* Write data pointed by the buffers described by IOVEC, which
   is a vector of COUNT 'struct iovec's, to file descriptor FD.
   The data is written in the order specified.
   Operates just like 'write' (see <unistd.h>) except that the data
   are taken from IOVEC instead of a contiguous buffer. */

typedef ssize_t (*orig_writev_type)(int __fd, const struct iovec *__iovec,
		int __count);
	
ssize_t writev (int __fd, const struct iovec *__iovec, int __count)
{
	fprintf(stderr, "writev() called!\n");
	orig_writev_type orig_writev;
	orig_writev = (orig_writev_type) dlsym(RTLD_NEXT, "writev");
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
	fprintf(stderr, "readv() called!\n");
	orig_readv_type orig_readv;
	orig_readv = (orig_readv_type) dlsym(RTLD_NEXT, "readv");
	return orig_readv(__fd, __iovec, __count); 
}   

/* Send up to COUNT bytes from file associated with IN_FD starting at
   *OFFSET to descriptor OUT_FD.  Set *OFFSET to the IN_FD's file position
   following the read bytes.  If OFFSET is a null pointer, use the normal
   file position instead.  Return the number of written bytes, or -1 in
   case of error.  */

typedef ssize_t (*orig_sendfile_type)(int __out_fd, int __in_fd,
		off_t *__offset, size_t __count);

ssize_t sendfile (int __out_fd, int __in_fd, off_t *__offset, size_t __count)
{
	fprintf(stderr, "sendfile() called!\n");
	orig_sendfile_type orig_sendfile;
	orig_sendfile = (orig_sendfile_type) dlsym(RTLD_NEXT, "sendfile");
	return orig_sendfile(__out_fd, __in_fd, __offset, __count); 
}   


