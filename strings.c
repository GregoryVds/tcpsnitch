#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "strings.h"
#include "lib.h"

/* Return a new string from a constant doign performing a lookup in a dict 
 * passed as argument. Called must free returned pointer.
 * Pre:
 * 	- cons: constant to be matched.
 *	- map: array of ConsStrPair which provides the mapping.
 *	- map_size: number of elements in map.
 */

char *build_string_from_cons(int cons, const IntStrPair *map, int map_size) {
	static const int str_size = MEMBER_SIZE(IntStrPair, str);
	int i;
	char *str = (char *)malloc(str_size);
 	const IntStrPair *cur;

	// Search for const in map.
	for (i = 0; i < map_size; i++) {
		cur = (map+i);
		if (cur->cons == cons) {
			strncpy(str, cur->str, str_size);
			return str; 
		}
	}
	
	// No match found, just write the constant digit.
	snprintf(str, str_size, "%d", cons);
	return str;
}
