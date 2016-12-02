#ifndef INIT_H
#define INIT_H

#include <stdbool.h>

extern char *tcpspy_dir;
extern long conf_bytes_ival;
extern long conf_micros_ival;
extern long conf_verbosity;

void reset_netspy(void);
void init_netspy(void);

#endif

