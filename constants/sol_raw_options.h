#include <linux/icmp.h>

static const IntStrPair SOL_RAW_OPTIONS[] = {
    ADD(ICMP_FILTER),
#include "_sol_ip_options.h"
};
