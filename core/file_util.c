#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "debug.h"

ssize_t try_get_file_image(void **buf, const char *fn)
{
	int fd;
	struct stat stat;
	ssize_t alloc_size;
	int i;

	*buf = NULL;
	if ((fd = open(fn, O_RDONLY)) < 0) {
		/* not found. not an error. */
		return 0;
	}
	if (fstat(fd, &stat) < 0) {
		app_error("failed to fstat %s\n", fn);
		goto err;
	}
	alloc_size = stat.st_size;
	if ((*buf = malloc(alloc_size)) == NULL) {
		app_error("%s(): memory allocation failed for %s\n",
			  __func__, fn);
		goto err;
	}
	if (read(fd, *buf, stat.st_size) < stat.st_size) {
		app_error("%s(): read failed for %s\n", __func__, fn);
		goto err;
	}
	close(fd);

	for (i = stat.st_size; i < alloc_size; i++)
		((char *)*buf)[i] = 0;
	return alloc_size;

err:
	close(fd);
	if (*buf) {
		free(*buf);
		*buf = NULL;
	}
	return -1;
}
