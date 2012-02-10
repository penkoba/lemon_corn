#include <stdio.h>
#include <string.h>
#include <stdarg.h>

char *strcatf(char *s, const char *form, ...)
{
	int len = strlen(s);
	va_list	pvar;

	va_start(pvar, form);
	vsprintf(&s[len], form, pvar);
	va_end(pvar);
	return s;
}
