#ifndef RESIABLZE_ARRAY_H
#define RESIABLZE_ARRAY_H

#include "sock_events.h"

#define ELEM_TYPE SocketState*  // Elements stored in the array.
#define FREE_ELEM(elem) \
        free_socket_state(elem)  // Routine for freeing an element.
#define MIN_INIT_SIZE 16         // Starting size of array.
#define GROWTH_FACTOR 2  // Minimum growth factor when the array is expanded.

bool ra_put_elem(int index, ELEM_TYPE elem);
ELEM_TYPE ra_remove_elem(int index);
ELEM_TYPE ra_get_and_lock_elem(int index);
void ra_unlock_elem(int index);

bool ra_is_present(int index);
int ra_get_size(void);

void ra_free(void);  // Free state.
void ra_reset(void);

#endif
