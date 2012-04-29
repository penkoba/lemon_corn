#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "file_util.h"
#include "lemon_corn_data.h"

#include "debug.h"

void lcdata_free(struct lcdata *lcdata)
{
	free(lcdata->ent_img);
}

void *lcdata_parse_ent(void *p, struct lcdata_ent *ent)
{
	struct lcdata_ent_img_var *vent = p;

	if (vent->dummy == 0) {	/* it's me. */
		ent->tag = vent->tag;
		ent->data = vent->data;
		ent->data_size = ((unsigned short)vent->len[0] << 8) |
				  (unsigned short)vent->len[1];
	} else {		/* nope. fixed size. */
		struct lcdata_ent_img_fxd *fent = p;
		ent->tag = fent->tag;
		ent->data = fent->data;
		ent->data_size = PCOPRS1_DATA_LEN;
	}
	return ent->data + ent->data_size;
}

int lcdata_get_cmd_by_tag(struct lcdata *lcdata, const char *tag,
			  struct lcdata_ent *ent)
{
	void *p, *nextp, *endp;

	lcdata_for_each_entry(lcdata, ent, p, nextp, endp) {
		if (!strcmp(tag, ent->tag))
			return 0;
	}

	/* not found */
	return -1;
}

int lcdata_delete_by_tag(struct lcdata *lcdata, const char *tag)
{
	struct lcdata_ent ent;
	void *p, *nextp, *endp;

	lcdata_for_each_entry(lcdata, &ent, p, nextp, endp) {
		if (!strcmp(tag, ent.tag)) {
			lcdata_ent_img_invalidate(p);
			return 0;
		}
	}

	/* not found */
	return -1;
}

int lcdata_load(struct lcdata *lcdata, const char *fn)
{
	ssize_t data_sz;

	if ((data_sz = try_get_file_image(&lcdata->ent_img, fn)) < 0)
		return -1;

	lcdata->img_size = data_sz;
	return 0;
}

int __lcdata_save(const struct lcdata *lcdata, const char *fn, int is_append)
{
	struct lcdata_ent ent;
	void *p, *nextp, *endp;
	int fd;

	if (is_append)
		fd = open(fn, O_WRONLY | O_APPEND);
	else
		fd = open(fn, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd < 0) {
		app_error("data file open failed: %s (%s)\n",
			  fn, strerror(errno));
		return -1;
	}

	lcdata_for_each_entry(lcdata, &ent, p, nextp, endp) {
		if (lcdata_ent_img_is_valid(p)) {
			if (write(fd, p, nextp - p) < 0)
				return -1;
		}
	}

	close(fd);
	return 0;
}
