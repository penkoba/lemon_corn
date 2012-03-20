#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "string_util.h"

#define DEBUG_HEAD_REMOCON_FORMAT	"[remocon format] "
#ifndef DEBUG_LEVEL_REMOCON_FORMAT
#define DEBUG_LEVEL_REMOCON_FORMAT	0
#endif
#include "debug.h"

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

#define DATA_LEN_MAX	64

enum analyzer_state {
	ANALIZER_STATE_LEADER,
	ANALIZER_STATE_DATA,
	ANALIZER_STATE_TRAILER,
	ANALIZER_STATE_MARKER,
	ANALIZER_STATE_REPEATER,
};

typedef struct analyzer analyzer_t;
struct analyzer {
	/*
	 * config
	 */
	const char *msg_head;
	int data_bit_len_min;
	int data_bit_len_max;
	int data_len;
	int leader_h_len_min;
	int leader_h_len_max;
	int leader_l_len_min;
	int leader_l_len_max;
	int trailer_l_len_min;
	int trailer_l_len_max;
	int cycle_len_min;
	int cycle_len_max;

	/*
	 * check function
	 */
	int (*check_dur0)(const analyzer_t *analyzer);
	int (*check_dur1)(const analyzer_t *analyzer);
	int (*check_unconditional)(const analyzer_t *analyzer);
	int (*set_dest)(const analyzer_t *analyzer,
			unsigned char *dst, const unsigned char *tmp);

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

static void analyzer_init(analyzer_t *analyzer)
{
	analyzer->dst_idx = 0;
	analyzer->cycle = 0;

	analyzer->state = ANALIZER_STATE_TRAILER;
	/* assuming we had enough 0s */
	analyzer->level = 0;
	analyzer->dur = analyzer->trailer_l_len_min;
	analyzer->dur_prev = 0;
	analyzer->dur_cycle = analyzer->cycle_len_min;
}

static inline char get_bit(const unsigned char *data, int idx)
{
	return (data[idx / 8] >> (idx & 0x7)) & 0x01;
}

static inline void set_bit(unsigned char *data, int idx)
{
	data[idx / 8] |= (1 << (idx & 0x7));
}

static int data_detected(const analyzer_t *analyzer, unsigned char *dst,
			 unsigned char bit)
{
	if (analyzer->dst_idx == analyzer->data_bit_len_max) {
		app_debug(REMOCON_FORMAT, 1, "%stoo long data\n",
			  analyzer->msg_head);
		return -1;
	}
	if (bit)
		set_bit(dst, analyzer->dst_idx);
	return 0;
}

static inline int check_on_flipped(analyzer_t *analyzer)
{
	app_debug(REMOCON_FORMAT, 3,
		  "%-4s at %3d, dur = %3d, dur_cycle = %3d\n",
		  (analyzer->level == 1) ? "HIGH" : "LOW", analyzer->src_idx,
		  analyzer->dur, analyzer->dur_cycle);

	if (analyzer->level == 0)
		return analyzer->check_dur0(analyzer);
	else	/* analyzer->level = 1 */
		return analyzer->check_dur1(analyzer);
}

static int set_dest(const analyzer_t *analyzer,
		    unsigned char *dst, const unsigned char *tmp)
{
	char dst_str[DATA_LEN_MAX * 2] = "";
	char tmp_str[DATA_LEN_MAX * 2] = "";
	int i;

	for (i = analyzer->data_len - 1; i >= 0; i--) {
		strcatf(dst_str, "%02x", dst[i]);
		strcatf(tmp_str, "%02x", tmp[i]);
	}

	app_debug(REMOCON_FORMAT, 1, "%scycle %d data got: %s\n",
		  analyzer->msg_head, analyzer->cycle, tmp_str);

	if (analyzer->cycle == 0)
		memcpy(dst, tmp, analyzer->data_len);
	else {
		if (memcmp(dst, tmp, analyzer->data_len)) {
			app_debug(REMOCON_FORMAT, 1,
				  "%sdata unmatched in cycles:\n"
				  " data 1: %s\n"
				  " data %d: %s\n",
				  analyzer->msg_head, dst_str,
				  analyzer->cycle + 1, tmp_str);
			return -1;
		}
	}

	return 0;
}

static inline int detect_trailer(const analyzer_t *analyzer)
{
	if ((analyzer->level == 0) &&
	    (analyzer->state == ANALIZER_STATE_DATA) &&
	    (analyzer->dur >= analyzer->trailer_l_len_min) &&
	    (analyzer->dur_cycle >= analyzer->cycle_len_min)) {
		if (analyzer->dst_idx < analyzer->data_bit_len_min) {
			app_debug(REMOCON_FORMAT, 1,
				  "%sdata length (%d) unmatched\n",
				  analyzer->msg_head, analyzer->dst_idx);
			return -1;
		}
		app_debug(REMOCON_FORMAT, 2, "%strailer detected at %d\n",
			  analyzer->msg_head, analyzer->src_idx);
		return DETECTED_PATTERN_TRAILER;
	}

	return 0;
}

static int check_unconditional(const analyzer_t *analyzer)
{
	int r = detect_trailer(analyzer);
	if (r == 0)
		r = analyzer->check_unconditional(analyzer);
	return r;
}

/*
 * NEC format
 * | leader | custom code | ~custom code | data code | ~data code |
 *   stop bit + frame space |
 *
 * leader:  ------------------------------...............  9.0ms / 4.5ms
 * data0:   -----.....                                     0.56ms / 0.56ms
 * data1:   -----.................                         0.56ms / 1.69ms
 * total 108 ms including frame space (checking 36ms for frame space is enough)
 *
 * repeat signal:
 * ------------------------------...............-----   9.0ms / 2.25m / 0.56ms
 *
 * custom code: 8 bit
 * data code:   8 bit
 */
#define NEC_DATA_H_LEN_MIN	5	/* typ = 6 */
#define NEC_DATA_H_LEN_MAX	6
#define NEC_DATA0_L_LEN_MIN	5	/* typ = 6 */
#define NEC_DATA0_L_LEN_MAX	6
#define NEC_DATA1_L_LEN_MIN	16	/* typ = 17 */
#define NEC_DATA1_L_LEN_MAX	18
#define NEC_REPEATER_L_LEN_MIN	21	/* typ = 23 */
#define NEC_REPEATER_L_LEN_MAX	24

static int nec_check_dur0(const analyzer_t *analyzer)
{
	if (analyzer->state == ANALIZER_STATE_LEADER) {
		if (analyzer->cycle == 0) {
			if ((analyzer->dur >= analyzer->leader_l_len_min) &&
			    (analyzer->dur <= analyzer->leader_l_len_max)) {
				app_debug(REMOCON_FORMAT, 2,
					  "%sleader detected at %d\n",
					  analyzer->msg_head,
					  analyzer->src_idx);
				return DETECTED_PATTERN_LEADER;
			}
		} else {	/* expect repeat signal */
			if ((analyzer->dur >= NEC_REPEATER_L_LEN_MIN) &&
			    (analyzer->dur <= NEC_REPEATER_L_LEN_MAX))
				return DETECTED_PATTERN_REPEATER_L;
		}
	} else if (analyzer->state == ANALIZER_STATE_DATA) {
		if ((analyzer->dur >= NEC_DATA0_L_LEN_MIN) &&
		    (analyzer->dur <= NEC_DATA0_L_LEN_MAX)) {
			app_debug(REMOCON_FORMAT, 2, "%sdata0 at %d\n",
				  analyzer->msg_head, analyzer->src_idx);
			return DETECTED_PATTERN_DATA0;
		} else if ((analyzer->dur >= NEC_DATA1_L_LEN_MIN) &&
			   (analyzer->dur <= NEC_DATA1_L_LEN_MAX)) {
			app_debug(REMOCON_FORMAT, 2, "%sdata1 at %d\n",
				  analyzer->msg_head, analyzer->src_idx);
			return DETECTED_PATTERN_DATA1;
		}
	} else if (analyzer->state == ANALIZER_STATE_TRAILER) {
		return DETECTED_PATTERN_TRAILER;
	}

	app_debug(REMOCON_FORMAT, 1,
		  "%sunmatched LOW duration (%d) at %d (state = %d)\n",
		  analyzer->msg_head, analyzer->dur, analyzer->src_idx,
		  analyzer->state);
	return -1;
}

static int nec_check_dur1(const analyzer_t *analyzer)
{
	if (analyzer->state == ANALIZER_STATE_LEADER) {
		if ((analyzer->dur >= analyzer->leader_h_len_min) &&
		    (analyzer->dur <= analyzer->leader_h_len_max))
			return 0;
	} else if (analyzer->state == ANALIZER_STATE_REPEATER) {
		if ((analyzer->dur >= NEC_DATA_H_LEN_MIN) &&
		    (analyzer->dur <= NEC_DATA_H_LEN_MAX)) {
			app_debug(REMOCON_FORMAT, 2,
				  "%srepeater detected at %d\n",
				  analyzer->msg_head, analyzer->src_idx);
			return DETECTED_PATTERN_REPEATER_H;
		}
	} else if (analyzer->state == ANALIZER_STATE_DATA) {
		if ((analyzer->dur >= NEC_DATA_H_LEN_MIN) &&
		    (analyzer->dur <= NEC_DATA_H_LEN_MAX))
			return 0;
	}

	app_debug(REMOCON_FORMAT, 1,
		  "%sunmatched HIGH duration (%d) at %d (state = %d)\n",
		   analyzer->msg_head, analyzer->dur, analyzer->src_idx,
		   analyzer->state);
	return -1;
}

static int nec_check_unconditional(const analyzer_t *analyzer)
{
	return 0;
}

static void nec_analyzer_init(analyzer_t *a)
{
	a->msg_head = "[NEC] ";
	a->data_bit_len_min = 32;
	a->data_bit_len_max = 32;
	a->data_len = 6;
	a->leader_h_len_min = 80;	/* typ = 90 */
	a->leader_h_len_max = 100;
	a->leader_l_len_min = 40;	/* typ = 45 */
	a->leader_l_len_max = 50;
	a->trailer_l_len_min = 360;	/* typ = ??? */
	a->trailer_l_len_max = 1000;
	a->cycle_len_min = 0;		/* no condition */
	a->cycle_len_max = 10000;	/* no condition */
	a->check_dur0 = nec_check_dur0;
	a->check_dur1 = nec_check_dur1;
	a->check_unconditional = nec_check_unconditional;
	a->set_dest = set_dest;
}


/*
 * Panasonic / SHARP format
 *
 * | leader | data | stop bit | trailer |
 * leader:  ------------------------------...............  3.5ms / 1.5ms
 * data0:   -----.....                                     0.4ms / 0.4ms
 * data1:   -----.................                         0.4ms / 1.2ms
 * trailer: ..............................                 20.0ms
 *
 * data: 48 bit
 */
#define PANA_DATA_H_LEN_MIN	3	/* typ = 4 */
#define PANA_DATA_H_LEN_MAX	5
#define PANA_DATA0_L_LEN_MIN	3	/* typ = 4 */
#define PANA_DATA0_L_LEN_MAX	5
#define PANA_DATA1_L_LEN_MIN	10	/* typ = 12 */
#define PANA_DATA1_L_LEN_MAX	14

static int pana_check_dur0(const analyzer_t *analyzer)
{
	if (analyzer->state == ANALIZER_STATE_LEADER) {
		if ((analyzer->dur >= analyzer->leader_l_len_min) &&
		    (analyzer->dur <= analyzer->leader_l_len_max)) {
			app_debug(REMOCON_FORMAT, 2,
				  "%sleader detected at %d\n",
				  analyzer->msg_head, analyzer->src_idx);
			return DETECTED_PATTERN_LEADER;
		}
	} else if (analyzer->state == ANALIZER_STATE_DATA) {
		if ((analyzer->dur >= PANA_DATA0_L_LEN_MIN) &&
		    (analyzer->dur <= PANA_DATA0_L_LEN_MAX)) {
			app_debug(REMOCON_FORMAT, 2, "%sdata0 at %d\n",
				  analyzer->msg_head, analyzer->src_idx);
			return DETECTED_PATTERN_DATA0;
		} else if ((analyzer->dur >= PANA_DATA1_L_LEN_MIN) &&
			   (analyzer->dur <= PANA_DATA1_L_LEN_MAX)) {
			app_debug(REMOCON_FORMAT, 2, "%sdata1 at %d\n",
				  analyzer->msg_head, analyzer->src_idx);
			return DETECTED_PATTERN_DATA1;
		}
	} else if (analyzer->state == ANALIZER_STATE_TRAILER) {
		return DETECTED_PATTERN_TRAILER;
	}

	app_debug(REMOCON_FORMAT, 1,
		  "%sunmatched LOW duration (%d) at %d (state = %d)\n",
		  analyzer->msg_head, analyzer->dur, analyzer->src_idx,
		  analyzer->state);
	return -1;
}

static int pana_check_dur1(const analyzer_t *analyzer)
{
	if (analyzer->state == ANALIZER_STATE_LEADER) {
		if ((analyzer->dur >= analyzer->leader_h_len_min) &&
		    (analyzer->dur <= analyzer->leader_h_len_max))
			return 0;
	} else if (analyzer->state == ANALIZER_STATE_DATA) {
		if ((analyzer->dur >= PANA_DATA_H_LEN_MIN) &&
		    (analyzer->dur <= PANA_DATA_H_LEN_MAX))
			return 0;
	}

	app_debug(REMOCON_FORMAT, 1,
		  "%sunmatched HIGH duration (%d) at %d (state = %d)\n",
		   analyzer->msg_head, analyzer->dur, analyzer->src_idx,
		   analyzer->state);
	return -1;
}

static int pana_check_unconditional(const analyzer_t *analyzer)
{
	return 0;
}

static void pana_analyzer_init(analyzer_t *a)
{
	a->msg_head = "[PANA] ";
	a->data_bit_len_min = 48;	/* SHARP dvd, Panasonic STB */
	a->data_bit_len_max = 48;
	a->data_len = 6;
	a->leader_h_len_min = 32;	/* typ = 35 */
	a->leader_h_len_max = 38;
	a->leader_l_len_min = 12;	/* typ = 15 */
	a->leader_l_len_max = 18;
	a->trailer_l_len_min = 180;	/* typ = 200 (SHARP dvd) */
	a->trailer_l_len_max = 220;
	a->cycle_len_min = 0;		/* no condition */
	a->cycle_len_max = 10000;	/* no condition */
	a->check_dur0 = pana_check_dur0;
	a->check_dur1 = pana_check_dur1;
	a->check_unconditional = pana_check_unconditional;
	a->set_dest = set_dest;
}

/*
 * SONY format
 * | leader | data | trailer |
 *
 * leader:  ------------------------......  2.4ms / 0.6ms
 * data0:   ------......                    0.6ms / 0.6ms
 * data1:   ------------......              1.2ms / 0.6ms
 * trailer: ..............................  leader + data + trailer = 45.0ms
 *
 * data: 7 bit for command, 5/8/13 bit for product ID
 */

#define SONY_DATA0_H_LEN_MIN	4	/* typ = 6 */
#define SONY_DATA0_H_LEN_MAX	8
#define SONY_DATA1_H_LEN_MIN	10	/* typ = 12 */
#define SONY_DATA1_H_LEN_MAX	14
#define SONY_DATA_L_LEN_MIN	4	/* typ = 6 */
#define SONY_DATA_L_LEN_MAX	8

static int sony_check_dur0(const analyzer_t *analyzer)
{
	if (analyzer->state == ANALIZER_STATE_LEADER) {
		/* didn't have enough 0 for leader */
	} else if (analyzer->state == ANALIZER_STATE_DATA) {
		if ((analyzer->dur >= SONY_DATA_L_LEN_MIN) &&
		    (analyzer->dur <= SONY_DATA_L_LEN_MAX))
			return 0;
	} else if (analyzer->state == ANALIZER_STATE_TRAILER)
		return DETECTED_PATTERN_TRAILER;

	app_debug(REMOCON_FORMAT, 1,
		  "%sunmatched LOW duration (%d) at %d (state = %d)\n",
		  analyzer->msg_head, analyzer->dur, analyzer->src_idx,
		  analyzer->state);
	return -1;
}

static int sony_check_dur1(const analyzer_t *analyzer)
{
	if (analyzer->state == ANALIZER_STATE_LEADER) {
		if ((analyzer->dur >= analyzer->leader_h_len_min) &&
		    (analyzer->dur <= analyzer->leader_h_len_max))
			return 0;
	} else
		return 0;

	app_debug(REMOCON_FORMAT, 1,
		  "%sunmatched HIGH duration (%d) at %d (state = %d)\n",
		   analyzer->msg_head, analyzer->dur, analyzer->src_idx,
		   analyzer->state);
	return -1;
}

static int sony_check_unconditional(const analyzer_t *analyzer)
{
	if ((analyzer->state == ANALIZER_STATE_LEADER) &&
	    (analyzer->level == 0) &&
	    (analyzer->dur == analyzer->leader_l_len_min)) {
		app_debug(REMOCON_FORMAT, 2, "%sleader detected at %d\n",
			  analyzer->msg_head, analyzer->src_idx);
		return DETECTED_PATTERN_LEADER;
	} else if ((analyzer->state == ANALIZER_STATE_DATA) &&
		   (analyzer->level == 0) &&
		   (analyzer->dur == SONY_DATA_L_LEN_MIN)) {
		if ((analyzer->dur_prev >= SONY_DATA0_H_LEN_MIN) &&
		    (analyzer->dur_prev <= SONY_DATA0_H_LEN_MAX)) {
			app_debug(REMOCON_FORMAT, 2, "%sdata0 at %d\n",
				  analyzer->msg_head, analyzer->src_idx);
			return DETECTED_PATTERN_DATA0;
		} else if ((analyzer->dur_prev >= SONY_DATA1_H_LEN_MIN) &&
			   (analyzer->dur_prev <= SONY_DATA1_H_LEN_MAX)) {
			app_debug(REMOCON_FORMAT, 2, "%sdata1 at %d\n",
				  analyzer->msg_head, analyzer->src_idx);
			return DETECTED_PATTERN_DATA1;
		}
	} else
		return 0;

	app_debug(REMOCON_FORMAT, 1,
		  "%sunmatched HIGH duration (%d) at %d (state = %d)\n",
		  analyzer->msg_head, analyzer->dur_prev,
		  analyzer->src_idx - analyzer->dur, analyzer->state);
	return -1;
}

static void sony_analyzer_init(analyzer_t *a)
{
	a->msg_head = "[SONY] ";
	a->data_bit_len_min = 12;	/* 12, 15, 20 bits */
	a->data_bit_len_max = 20;
	a->data_len = 3;
	a->leader_h_len_min = 21;	/* typ = 24 */
	a->leader_h_len_max = 27;
	a->leader_l_len_min = 4;	/* typ = 6 */
	a->leader_l_len_max = 8;
	a->trailer_l_len_min = 60;	/* arbitrary */
	a->trailer_l_len_max = 200;	/* arbitrary */
	a->cycle_len_min = 400;		/* typ = 450 */
	a->cycle_len_max = 500;
	a->check_dur0 = sony_check_dur0;
	a->check_dur1 = sony_check_dur1;
	a->check_unconditional = sony_check_unconditional;
	a->set_dest = set_dest;
};

/*
 * Koizumi ceiling fan
 *
 * | start bit | data | trailer |
 * start bit:  ---------                            0.83ms
 * data0:   ................--------                1.67ms / 0.83ms
 * data1:   ........----------------                0.83ms / 1.67ms
 * separator: ...................................   5.0ms
 * trailer: .....................................  13.2ms
 *
 * data: 48 bit
 */
#define KOIZ_DATA0_L_LEN_MIN	15	/* typ = 16.7 */
#define KOIZ_DATA0_L_LEN_MAX	19
#define KOIZ_DATA0_H_LEN_MIN	7	/* typ = 8.3 */
#define KOIZ_DATA0_H_LEN_MAX	10
#define KOIZ_DATA1_L_LEN_MIN	7	/* typ = 8.3 */
#define KOIZ_DATA1_L_LEN_MAX	10
#define KOIZ_DATA1_H_LEN_MIN	15	/* typ = 16.7 */
#define KOIZ_DATA1_H_LEN_MAX	19
#define KOIZ_MARKER_L_LEN_MIN	45	/* typ = 50 */
#define KOIZ_MARKER_L_LEN_MAX	55
#define KOIZ_MARKER_BIT_POS1	9
#define KOIZ_MARKER_BIT_POS2	12

static int koiz_check_dur0(const analyzer_t *analyzer)
{
	if (analyzer->state == ANALIZER_STATE_TRAILER)
		return DETECTED_PATTERN_TRAILER;
	return 0;
}

static int koiz_check_dur1(const analyzer_t *analyzer)
{
	if (analyzer->state == ANALIZER_STATE_LEADER) {
		if ((analyzer->dur >= analyzer->leader_h_len_min) &&
		    (analyzer->dur <= analyzer->leader_h_len_max))
			return 0;
	} else if (analyzer->state == ANALIZER_STATE_DATA) {
		if ((analyzer->dur_prev >= KOIZ_DATA0_L_LEN_MIN) &&
		    (analyzer->dur_prev <= KOIZ_DATA0_L_LEN_MAX) &&
		    (analyzer->dur >= KOIZ_DATA0_H_LEN_MIN) &&
		    (analyzer->dur <= KOIZ_DATA0_H_LEN_MAX)) {
			app_debug(REMOCON_FORMAT, 2, "%sdata0 at %d\n",
				  analyzer->msg_head, analyzer->src_idx);
			return DETECTED_PATTERN_DATA0;
		} else if ((analyzer->dur_prev >= KOIZ_DATA1_L_LEN_MIN) &&
			   (analyzer->dur_prev <= KOIZ_DATA1_L_LEN_MAX) &&
			   (analyzer->dur >= KOIZ_DATA1_H_LEN_MIN) &&
			   (analyzer->dur <= KOIZ_DATA1_H_LEN_MAX)) {
			app_debug(REMOCON_FORMAT, 2, "%sdata1 at %d\n",
				  analyzer->msg_head, analyzer->src_idx);
			return DETECTED_PATTERN_DATA1;
		} else if ((analyzer->dur_prev >= KOIZ_MARKER_L_LEN_MIN) &&
			   (analyzer->dur_prev <= KOIZ_MARKER_L_LEN_MAX) &&
			   (analyzer->dur >= analyzer->leader_h_len_min) &&
			   (analyzer->dur <= analyzer->leader_h_len_max)) {
			if ((analyzer->dst_idx != KOIZ_MARKER_BIT_POS1) &&
			    (analyzer->dst_idx != KOIZ_MARKER_BIT_POS2)) {
				app_debug(REMOCON_FORMAT, 2,
					  "%sunexpected marker position (%d)"
					  " at %d\n",
					  analyzer->msg_head, analyzer->dst_idx,
					  analyzer->src_idx);
				return -1;
			}
			app_debug(REMOCON_FORMAT, 2, "%smarker at %d\n",
				  analyzer->msg_head, analyzer->src_idx);
			return DETECTED_PATTERN_MARKER;
		}
	} else
		return 0;

	app_debug(REMOCON_FORMAT, 1,
		  "%sunmatched pattern: LOW duration (%d) / HIGH duration (%d)"
		  " at %d (state = %d)\n",
		   analyzer->msg_head, analyzer->dur_prev, analyzer->dur,
		   analyzer->src_idx, analyzer->state);
	return -1;
}

static int koiz_check_unconditional(const analyzer_t *analyzer)
{
	if ((analyzer->state == ANALIZER_STATE_LEADER) &&
	    (analyzer->level == 0) &&
	    (analyzer->dur == analyzer->leader_l_len_min)) {
		app_debug(REMOCON_FORMAT, 2, "%sleader detected at %d\n",
			  analyzer->msg_head, analyzer->src_idx);
		return DETECTED_PATTERN_LEADER;
	} else
		return 0;

	app_debug(REMOCON_FORMAT, 1,
		  "%sunmatched HIGH duration (%d) at %d (state = %d)\n",
		  analyzer->msg_head, analyzer->dur_prev,
		  analyzer->src_idx - analyzer->dur, analyzer->state);
	return -1;
}

static int koiz_set_dest(const analyzer_t *analyzer,
			 unsigned char *dst, const unsigned char *tmp)
{
	char dst_str[DATA_LEN_MAX * 2] = "";
	char tmp_str[DATA_LEN_MAX * 2] = "";
	int i;

	for (i = analyzer->data_len - 1; i >= 0; i--) {
		strcatf(dst_str, "%02x", dst[i]);
		strcatf(tmp_str, "%02x", tmp[i]);
	}

	app_debug(REMOCON_FORMAT, 1, "%scycle %d data got: %s\n",
		  analyzer->msg_head, analyzer->cycle, tmp_str);

	/*
	 * cycle1:           command only
	 * cycle2 and after: command + id + command
	 */
	if (analyzer->cycle == 0)
		memcpy(dst, tmp, analyzer->data_len);
	else if (analyzer->cycle == 1) {
		unsigned short dst_cmd, tmp_cmd1, tmp_cmd2;
		dst_cmd = (dst[1] << 8) | dst[0];
		tmp_cmd1 = (((unsigned short)tmp[1] << 8) | tmp[0]) & 0x1ff;
		tmp_cmd2 = (((unsigned short)tmp[2] << 4) |
			    ((unsigned short)tmp[1] >> 4)) & 0x1ff;
		if ((dst_cmd != tmp_cmd1) ||
		    (dst_cmd != tmp_cmd2)) {
			app_debug(REMOCON_FORMAT, 1,
				  "%scommand unmatched in second stage:\n"
				  " first cmd: %04x\n"
				  " second cmd1: %04x, cmd2: %04x\n",
				  analyzer->msg_head,
				  dst_cmd, tmp_cmd1, tmp_cmd2);
			return -1;
		}
		memcpy(dst, tmp, analyzer->data_len);
	} else {
		if (memcmp(dst, tmp, analyzer->data_len)) {
			app_debug(REMOCON_FORMAT, 1,
				  "%sdata unmatched in cycles:\n"
				  " data 1: %s\n"
				  " data %d: %s\n",
				  analyzer->msg_head, dst_str,
				  analyzer->cycle + 1, tmp_str);
			return -1;
		}
	}

	return 0;
}

static void koiz_analyzer_init(analyzer_t *a)
{
	a->msg_head = "[KOIZ] ";
	a->data_bit_len_min = 9;	/* 9 or 9 + 3 + 9 */
	a->data_bit_len_max = 21;
	a->data_len = 3;
	a->leader_h_len_min = 7;	/* typ = 8.3 */
	a->leader_h_len_max = 10;
	a->leader_l_len_min = 7;	/* typ = 8.3 or 16.7 */
	a->leader_l_len_max = 19;

	a->trailer_l_len_min = 119;	/* typ = 132 */
	a->trailer_l_len_max = 145;
	a->cycle_len_min = 0;		/* no condition */
	a->cycle_len_max = 10000;	/* no condition */
	a->check_dur0 = koiz_check_dur0;
	a->check_dur1 = koiz_check_dur1;
	a->check_unconditional = koiz_check_unconditional;
	a->set_dest = koiz_set_dest;
}

/*
 * generic analyzer func
 */
static int analyze(analyzer_t *analyzer, unsigned char *dst,
		   const unsigned char *data, size_t sz)
{
	unsigned char dst_tmp[DATA_LEN_MAX] = { 0 };
	size_t sz_bit = sz * 8;
	int r;

	analyzer_init(analyzer);
	for (analyzer->src_idx = 0;
	     analyzer->src_idx < sz_bit;
	     analyzer->src_idx++) {
		char this_bit = get_bit(data, analyzer->src_idx);

		if ((analyzer->state == ANALIZER_STATE_DATA) ||
		    (analyzer->state == ANALIZER_STATE_TRAILER))
			analyzer->dur_cycle++;

		if (this_bit == analyzer->level) {
			analyzer->dur++;
		} else {
			r = check_on_flipped(analyzer);
			if (r < 0)
				return -1;
			else if (r == DETECTED_PATTERN_LEADER) {
				analyzer->state = ANALIZER_STATE_DATA;
				analyzer->dst_idx = 0;
				analyzer->dur_cycle =
					analyzer->dur_prev + analyzer->dur;
			} else if (r == DETECTED_PATTERN_TRAILER) {
				analyzer->state = ANALIZER_STATE_LEADER;
				analyzer->dur_cycle = 1;
			} else if (r == DETECTED_PATTERN_MARKER) {
				/* nothing to do */
			} else if (r == DETECTED_PATTERN_REPEATER_L) {
				analyzer->state = ANALIZER_STATE_REPEATER;
			} else if (r == DETECTED_PATTERN_REPEATER_H) {
				analyzer->state = ANALIZER_STATE_TRAILER;
			} else if (r > 0) {	/* data */
				int dat = (r == DETECTED_PATTERN_DATA1) ? 1 : 0;
				if (data_detected(analyzer, dst_tmp, dat) < 0)
					return -1;
				analyzer->dst_idx++;
			}

			analyzer->level = this_bit;
			analyzer->dur_prev = analyzer->dur;
			analyzer->dur = 1;
		}

		r = check_unconditional(analyzer);
		if (r < 0)
			return -1;
		else if (r == DETECTED_PATTERN_LEADER) {
			analyzer->state = ANALIZER_STATE_DATA;
			analyzer->dst_idx = 0;
			analyzer->dur_cycle =
				analyzer->dur_prev + analyzer->dur;
		} else if (r == DETECTED_PATTERN_TRAILER) {
			if (analyzer->set_dest(analyzer, dst, dst_tmp) < 0)
				return -1;
			analyzer->cycle++;
			analyzer->state = ANALIZER_STATE_TRAILER;
		} else if (r == DETECTED_PATTERN_MARKER) {
			/* nothing to do */
		} else if (r > 0) {	/* data */
			int dat = (r == DETECTED_PATTERN_DATA1) ? 1 : 0;
			if (data_detected(analyzer, dst_tmp, dat) < 0)
				return -1;
			analyzer->dst_idx++;
		}
	}

	if (analyzer->cycle == 0) {
		app_debug(REMOCON_FORMAT, 1, "%sno data cycle detected\n",
			  analyzer->msg_head);
		return -1;
	}

	return analyzer->data_len;
}

int remocon_format_analyze(char *fmt_tag, char *dst,
			   const unsigned char *data, size_t sz)
{
	unsigned char buf[DATA_LEN_MAX];
	analyzer_t analyzer;

	pana_analyzer_init(&analyzer);
	if (analyze(&analyzer, buf, data, sz) >= 0) {
		strcpy(fmt_tag, "PANA");
		sprintf(dst, "%02x%02x%02x%02x%02x%02x",
			buf[5], buf[4], buf[3], buf[2], buf[1], buf[0]);
		return 0;
	}

	nec_analyzer_init(&analyzer);
	if (analyze(&analyzer, buf, data, sz) >= 0) {
		unsigned char custom = buf[0];
		unsigned char cmd = buf[2];
		if ((buf[0] != (unsigned char)~buf[1]) ||
		    (buf[2] != (unsigned char)~buf[3])) {
			app_debug(REMOCON_FORMAT, 1,
				  "NEC pattern detected, but"
				  " data is inconsistent.\n"
				  "%02x%02x%02x%02x",
				  buf[0], buf[1], buf[2], buf[3]);
			return -1;
		}
		strcpy(fmt_tag, "NEC");
		sprintf(dst, "%02x %02x", custom, cmd);
		return 0;
	}

	sony_analyzer_init(&analyzer);
	if (analyze(&analyzer, buf, data, sz) >= 0) {
		unsigned char cmd;
		unsigned short prod;

		cmd = buf[0] & 0x7f;
		prod = ((unsigned short)buf[2] << 9) |
		       ((unsigned short)buf[1] << 1) |
		       (buf[0] >> 7);
		strcpy(fmt_tag, "SONY");
		sprintf(dst, "%02x %04x", cmd, prod);
		return 0;
	}

	koiz_analyzer_init(&analyzer);
	if (analyze(&analyzer, buf, data, sz) >= 0) {
		unsigned char id;
		unsigned short cmd;

		id = (buf[1] >> 1) & 0x7;
		cmd = (((unsigned short)buf[1] << 8) | buf[0]) & 0x1ff;
		strcpy(fmt_tag, "KOIZ");
		sprintf(dst, "%02x %04x", id, cmd);
		return 0;
	}

	return -1;
}
