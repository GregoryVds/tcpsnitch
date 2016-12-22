#ifndef RESIABLZE_ARRAY_H
#define RESIABLZE_ARRAY_H

#include "tcp_events.h"

/* This module provides a resizable array data structure with support for 
 * multithreaded applications. The caller may "lock" a given position of the
 * array and release it later. Any other call trying to access the locked 
 * element will block untill it is released.
 * 
 * In our case, this allows to have fine-grained mutexes. Rather than locking
 * the entire structure, with an array it is easy to only lock a given position
 * in order to have the mininal contention on the mutexes.
 *
 * A downside is that this array might be sparse. We will see in the future how
 * spase it gets.*/

#define ELEM_TYPE TcpConnection * // Elements stored in the array.
#define FREE_ELEM(elem) free_connection(elem) // Routine for freeing an element.
#define MIN_INIT_SIZE 16 // Starting size of array.
#define GROWTH_FACTOR 2 // Minimum growth factor when the array is expanded.

bool ra_put_elem(int index, ELEM_TYPE elem);
TcpConnection *ra_get_and_lock_elem(int index);
bool ra_unlock_elem(int index);

bool ra_is_present(int index);
int ra_get_size(void);

void ra_free(void); // Free state.
// Free state and restore to default state (called after fork()).
void ra_reset(void);

#endif

