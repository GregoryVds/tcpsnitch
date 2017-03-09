#ifndef INIT_H
#define INIT_H

#include <stdbool.h>
#include <stdio.h>

extern long conf_opt_b;
extern long conf_opt_c;
extern char *conf_opt_d;
extern long conf_opt_f;
extern char *conf_opt_i;
extern long conf_opt_l;
extern long conf_opt_p;
extern long conf_opt_u;
extern long conf_opt_t;
extern long conf_opt_v;

extern char *logs_dir_path;

#ifndef __ANDROID__
extern FILE *_stdout;
extern FILE *_stderr;
#endif

void reset_tcpsnitch(void);
void init_tcpsnitch(void);

#endif
