#ifndef _STRING_UTIL_H
#define _STRING_UTIL_H

#include <string.h>

static inline char *strchomp(char *s)
{
	size_t len = strlen(s);
	if (s[len - 1] == '\n')
		s[len - 1] = '\0';
	return s;
}

extern char *strcatf(char *s, const char *form, ...);

#endif	/* _STRING_UTIL_H */
