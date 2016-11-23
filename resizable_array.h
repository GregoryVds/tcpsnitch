#ifndef RESIABLZE_ARRAY_H
#define RESIABLZE_ARRAY_H

#include "tcp_spy.h"

#define ELEM_TYPE TcpConnection *
#define FREE_ELEM(elem) free_connection(elem)

#define MIN_INIT_SIZE 16
#define GROWTH_FACTOR 2

bool ra_put_elem(int index, ELEM_TYPE elem);
TcpConnection *ra_get_and_lock_elem(int index);
bool ra_unlock_elem(int index);
void ra_reset(void);
void ra_free(void);
int ra_get_size(void);
bool ra_is_present(int index);

#endif


