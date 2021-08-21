#pragma once
#include <stdlib.h>     /* strtol */
#include <limits.h>     /* LONG_MIN and LONG_MAX */
#include <errno.h>      /* ERANGE */

int str_to_long(const char *str, long *val)
{
	char *endptr;

	*val = strtol(str, &endptr, 10);
	if (endptr == str || (*endptr != '\0' && *endptr != '\n') ||
	    ((*val == LONG_MIN || *val == LONG_MAX) && errno == ERANGE))
		return -EINVAL;
	return 0;
}
