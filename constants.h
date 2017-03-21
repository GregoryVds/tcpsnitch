#ifndef CONFIG_H
#define CONFIG_H

#define STDOUT_FD 3
#define STDERR_FD 4

#ifdef __ANDROID__
#define OPT_B "be.ucl.tcpsnitch.opt_b"
#define OPT_C "be.ucl.tcpsnitch.opt_c"
#define OPT_D "be.ucl.tcpsnitch.opt_d"
#define OPT_F "be.ucl.tcpsnitch.opt_f"
#define OPT_L "be.ucl.tcpsnitch.opt_l"
#define OPT_P "be.ucl.tcpsnitch.opt_p"
#define OPT_T "be.ucl.tcpsnitch.opt_t"
#define OPT_U "be.ucl.tcpsnitch.opt_u"
#define OPT_V "be.ucl.tcpsnitch.opt_v"
#else
#define OPT_B "TCPSNITCH_OPT_B"
#define OPT_C "TCPSNITCH_OPT_C"
#define OPT_D "TCPSNITCH_OPT_D"
#define OPT_F "TCPSNITCH_OPT_F"
#define OPT_I "TCPSNITCH_OPT_I"
#define OPT_L "TCPSNITCH_OPT_L"
#define OPT_P "TCPSNITCH_OPT_P"
#define OPT_T "TCPSNITCH_OPT_T"
#define OPT_U "TCPSNITCH_OPT_U"
#define OPT_V "TCPSNITCH_OPT_V"
#endif

#endif
