#ifndef INIT_H
#define INIT_H

#include <stdbool.h>

extern char *tcpspy_dir;
extern long tcp_info_bytes_ival;
extern long tcp_info_micros_ival;

void reset_netspy(void);
void init_netspy(void);

#endif

