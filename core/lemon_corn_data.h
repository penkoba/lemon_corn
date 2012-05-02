#ifndef _LEMON_CORN_DATA_H
#define _LEMON_CORN_DATA_H

#include "PC-OP-RS1.h"

#define LEMON_CORN_TAG_LEN	32

/*
 * lcdata_ent has 2 types:
 *
 *   [fixed size]
 *     tag:   command tag string
 *     data:  size is PCOPRS1_DATA_LEN
 *
 *   [variable size]
 *     dummy: 0
 *     type:  1
 *     len:   the length of the data (big endian)
 *     tag:   command tag string
 *     data:  size is @len
 *
 *   when invalidating the entry, set 0 to first 2 bytes.
 *
 */
struct lcdata_ent_img_fxd {
	char tag[LEMON_CORN_TAG_LEN];
	unsigned char data[0];
};
struct lcdata_ent_img_var {
	unsigned char dummy;
	unsigned char type;
	unsigned char len[2];
	char tag[LEMON_CORN_TAG_LEN];
	unsigned char data[0];
};

#define lcdata_ent_img_invalidate(ent_img) \
	do { \
		((struct lcdata_ent_img_var *)ent_img)->dummy = 0; \
		((struct lcdata_ent_img_var *)ent_img)->type = 0; \
	} while (0)

#define lcdata_ent_img_is_valid(ent_img) \
	((((struct lcdata_ent_img_var *)ent_img)->dummy != 0) || \
	 (((struct lcdata_ent_img_var *)ent_img)->type != 0))

#define lcdata_ent_img_var_initialize(ventp, __len) \
	do { \
		(ventp)->dummy = 0; \
		(ventp)->type = 1; \
		(ventp)->len[0] = (unsigned char)((__len) >> 8); \
		(ventp)->len[1] = (unsigned char)((__len) & 0xff); \
	} while (0)

struct lcdata_ent {
	char *tag;
	unsigned char *data;
	unsigned short data_size;
};

struct lcdata {
	int img_size;
	void *ent_img;
};

#define lcdata_for_each_entry(lcdata, entp, p, nextp, endp) \
	for (p = (lcdata)->ent_img, \
		endp = (lcdata)->ent_img + (lcdata)->img_size, \
		nextp = (p < endp) ? lcdata_parse_ent(p, entp) : NULL; \
	     p < endp; \
	     p = nextp, nextp = (p < endp) ? lcdata_parse_ent(p, entp) : NULL)

extern void
lcdata_free(struct lcdata *lcdata);
extern void
*lcdata_parse_ent(void *p, struct lcdata_ent *ent);
extern int
lcdata_get_cmd_by_tag(struct lcdata *lcdata, const char *tag,
		      struct lcdata_ent *ent);
extern int
lcdata_delete_by_tag(struct lcdata *lcdata, const char *tag);
extern int
lcdata_load(struct lcdata *lcdata, const char *fn);
extern int
__lcdata_save(const struct lcdata *lcdata, const char *fn, int is_append);
#define lcdata_save(lcdata, fn)		__lcdata_save(lcdata, fn, 0)
#define lcdata_save_append(lcdata, fn)	__lcdata_save(lcdata, fn, 1)

#endif	/* _LEMON_CORN_DATA_H */
