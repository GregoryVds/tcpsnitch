#include <linux/icmp.h>

static const IntStrPair SOL_RAW_OPTIONS[] = {
#ifdef ICMP_FILTER
    ADD(ICMP_FILTER),
#endif
#include "_sol_ip_options.h"
};
