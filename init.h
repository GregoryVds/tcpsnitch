#ifndef INIT_H
#define INIT_H

#include <stdbool.h>
#include <stdio.h>

extern char *conf_dir;
extern long conf_bytes_ival;
extern long conf_micros_ival;
extern long conf_verbosity;

extern FILE *_stdout;
extern FILE *_stderr;

void reset_netspy(void);
void init_netspy(void);

#endif

