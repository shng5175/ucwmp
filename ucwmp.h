#ifndef UCWMP_H
#define UCWMP_H

#include <stdio.h>

#define err(fmt, args...) \
	fprintf(stderr, "%s: " fmt, __FUNCTION__, ##args)

#define CWMP_COMMAND_KEY_MAXLEN 256

#endif
