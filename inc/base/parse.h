#pragma once
#include <stdlib.h>     /* strtol */
#include <limits.h>     /* LONG_MIN and LONG_MAX */
#include <errno.h>      /* ERANGE */
#include <net/ethernet.h>

int str_to_mac(const char *s, struct eth_addr *mac_out) {
    unsigned int values[ETH_ADDR_LEN];
    int ret = sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x%*c", &values[0], &values[1], &values[2], &values[3],&values[4], &values[5]);
    if (6 != ret) {
        printf("Scan of mac addr %s was not 6, but length %d\n", s, ret);
        return EINVAL;
    }
    for (int i = 0; i < ETH_ADDR_LEN; i++) {
        mac_out->addr[i] = (uint8_t)values[i];
    }

    return 0;
}


int str_to_long(const char *str, long *val)
{
	char *endptr;

	*val = strtol(str, &endptr, 10);
	if (endptr == str || (*endptr != '\0' && *endptr != '\n') ||
	    ((*val == LONG_MIN || *val == LONG_MAX) && errno == ERANGE))
		return -EINVAL;
	return 0;
}
