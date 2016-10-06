#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include "lib.h"

const char *string_from_debug_level(DebugLevel lvl) {
	static const char *strings[] = { "INFO", "WARN", "ERROR" };
	return strings[lvl];
}

bool is_socket(int fd)
{
	struct stat statbuf;
	fstat(fd, &statbuf);
	return S_ISSOCK(statbuf.st_mode);
}

/* Allows to get a string from a constant.
 * Pre:
 * 	- cons: constant to be matched.
 * 	- buffer: pointer to a char array for writing the matched string.
 *	- buffer_size: size of the buffer char array.
 *	- map: array of ConsStrPair which provides the mapping.
 *	- map_size: number of elements in map.
 * Post:
 * 	- buffer: holds the string corresponding to the constant. If the
 * 	mapping was not found, then contain the constant number as a string.
 * Return:
 * 	- 1 if found a match
 * 	- 0 otherwise
 */

int string_from_cons(int cons, char *buffer, int buffer_size, 
		const IntStrPair *map, int map_size)
{
	int i;
	for (i=0; i<map_size; i++) {
		if ((map+i)->cons==cons) {
			strncpy(buffer, (map+i)->str, buffer_size);
			return 1;
		}
	}
	// No match found, just write the constant digit.
	snprintf(buffer, buffer_size, "%d", cons);
	return 0;
}

