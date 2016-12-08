#ifndef INIT_H
#define INIT_H

#include <stdbool.h>
#include <stdio.h>


extern long conf_opt_b;
extern char *conf_opt_d;
extern long conf_opt_f;
extern char *conf_opt_i;
extern long conf_opt_l;
extern long conf_opt_p;
extern long conf_opt_u;
extern long conf_opt_v;

extern FILE *_stdout;
extern FILE *_stderr;

void reset_tcpsnitch(void);
void init_tcpsnitch(void);

#endif

