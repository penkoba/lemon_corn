#ifndef _ANALYZER_COMMON_H
#define _ANALYZER_COMMON_H

#define DEBUG_HEAD_ANALYZER	"[analyzer] "
#ifndef DEBUG_LEVEL_ANALYZER
#define DEBUG_LEVEL_ANALYZER	0
#endif
#include "../debug.h"

#define UNUSED(x)	(void)(x)

/*
 * maximum analyzer data length
 */
#define ANALYZER_DATA_LEN_MAX  64

/*
 * enum to indicate what data an analyzer detected
 */
enum {
	DETECTED_PATTERN_DATA0 = 1,
	DETECTED_PATTERN_DATA1,
	DETECTED_PATTERN_DATA,
	DETECTED_PATTERN_LEADER,
	DETECTED_PATTERN_TRAILER,
	DETECTED_PATTERN_MARKER,
	DETECTED_PATTERN_REPEATER_L,
	DETECTED_PATTERN_REPEATER_H,
};

/*
 * analyzer state
 */
enum analyzer_state {
	ANALYZER_STATE_LEADER,
	ANALYZER_STATE_DATA,
	ANALYZER_STATE_TRAILER,
	ANALYZER_STATE_MARKER,
	ANALYZER_STATE_REPEATER,
};

/*
 * pre-define analyzer_t
 */
typedef struct analyzer analyzer_t;

/*
 * analyzer configuration
 */
struct analyzer_config {
	const char *fmt_tag;
	int data_len;
	int leader_h_len_min;
	int leader_h_len_max;
	int leader_l_len_min;
	int leader_l_len_max;
	int trailer_l_len_min;
	int trailer_l_len_max;
	int cycle_len_min;
	int cycle_len_max;
};

/*
 * analyzer operators
 */
struct analyzer_ops {
	int (*on_flip_up)(const analyzer_t *azer);
	int (*on_flip_dn)(const analyzer_t *azer);
	int (*on_each_sample)(const analyzer_t *azer);
	int (*on_end_cycle)(const analyzer_t *azer,
			    unsigned char *buf, const unsigned char *tmp,
			    char *dst_str);
	int (*on_exit)(const analyzer_t *azer, unsigned char *buf,
		       char *dst_str);
};

/*
 * analyzer struct
 */
struct analyzer {
	const struct analyzer_config *cfg;
	const struct analyzer_ops *ops;

	/*
	 * state
	 */
	enum analyzer_state state;
	int src_idx, dst_idx;
	int cycle;
	char level;
	int dur;
	int dur_prev;
	int dur_cycle;
};

#endif	/* _ANALYZER_COMMON_H */
