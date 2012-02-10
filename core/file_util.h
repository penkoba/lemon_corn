#ifndef _FILE_UTIL_H
#define _FILE_UTIL_H

#include <unistd.h>

extern ssize_t try_get_file_image(void **buf, const char *fn);

#endif	/* _FILE_UTIL_H */
