#include <stdbool.h> // boolean types
#include <sys/types.h> // stat
#include <sys/stat.h> // stat
#include <unistd.h> // stat

bool is_socket(int fd)
{
	struct stat statbuf;
	fstat(fd, &statbuf);
	return S_ISSOCK(statbuf.st_mode);
}

