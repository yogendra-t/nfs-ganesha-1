/*
 * Applications opening /etc/netgroup will end up opening
 * /etc/netgroup.nested instead. This is specifically written to work
 * with flat-netgr python script.
 *
 * Compile as below:
 * cc -Wall -fPIC -shared -o mynetgroup.so mynetgroup.c -ldl
 *
 * And place the mynetgroup.so in /usr/lpp/mmfs/bin directory!
 */

#define _GNU_SOURCE /* For RTLD_NEXT */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

FILE *fopen(const char *path, const char *mode)
{

	FILE *(*real_fopen)(const char *, const char *);

	real_fopen = dlsym(RTLD_NEXT, "fopen");
	if (strcmp(path, "/etc/netgroup") == 0)
		path = "/etc/netgroup.nested";
	return real_fopen(path, mode);
}
