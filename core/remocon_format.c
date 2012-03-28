/*
 * Copyright (c) 2012 Toshihiro Kobayashi <kobacha@mwa.biglobe.ne.jp>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
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

static inline char get_bit_in_ary(const unsigned char *ary, int idx)
{
	return (ary[idx / 8] >> (idx & 0x7)) & 0x01;
}

static inline void set_bit_in_ary(unsigned char *ary, int idx)
{
	ary[idx / 8] |= (1 << (idx & 0x7));
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
		set_bit_in_ary(dst, analyzer->dst_idx);
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

typedef struct {
	unsigned long t;	/* time in us */
	unsigned long t_flip;
	unsigned char *ptn;
	size_t ptn_len;
} forger_t;

static void forger_init(forger_t *forger, unsigned char *ptn, size_t ptn_len)
{
	forger->t = 0;
	forger->t_flip = 0;
	forger->ptn = ptn;
	forger->ptn_len = ptn_len;
	memset(ptn, 0, ptn_len);
}

static void forge_dur(forger_t *forger, int val, int dur)
{
	for (forger->t_flip += dur;
	     forger->t < forger->t_flip;
	     forger->t += 100) {
		if (val)
			set_bit_in_ary(forger->ptn, forger->t / 100);
	}
}

static void forge_until(forger_t *forger, int val, int until)
{
	for (forger->t_flip = until;
	     forger->t < forger->t_flip;
	     forger->t += 100) {
		if (val)
			set_bit_in_ary(forger->ptn, forger->t / 100);
	}
}

static void forge_pulse(forger_t *forger, int h_len, int l_len)
{
	forge_dur(forger, 1, h_len);
	forge_dur(forger, 0, l_len);
}

/*
 * NEC format
 * | leader | custom | custom' | data | ~data |
 *   stop bit + frame space |
 *
 * NOTE: custom' is not always ~custom !!
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
#define NEC_LEADER_H_LEN_MIN	  8000
#define NEC_LEADER_H_LEN_TYP	  9000
#define NEC_LEADER_H_LEN_MAX	 10000
#define NEC_LEADER_L_LEN_MIN	  4000
#define NEC_LEADER_L_LEN_TYP	  4500
#define NEC_LEADER_L_LEN_MAX	  5000
#define NEC_DATA_H_LEN_MIN	   500
#define NEC_DATA_H_LEN_TYP	   560
#define NEC_DATA_H_LEN_MAX	   620
#define NEC_DATA0_L_LEN_MIN	   500
#define NEC_DATA0_L_LEN_TYP	   560
#define NEC_DATA0_L_LEN_MAX	   620
#define NEC_DATA1_L_LEN_MIN	  1600
#define NEC_DATA1_L_LEN_TYP	  1690
#define NEC_DATA1_L_LEN_MAX	  1800
#define NEC_TRAILER_L_LEN_MIN	 36000
/* #define NEC_TRAILER_L_LEN_TYP */
#define NEC_TRAILER_L_LEN_MAX	150000	/* FIXME */
#define NEC_CYCLE_LEN_MIN	 80000
#define NEC_CYCLE_LEN_TYP	108000
#define NEC_CYCLE_LEN_MAX	150000
#define NEC_REPEATER_H_LEN_MIN	  8000
#define NEC_REPEATER_H_LEN_TYP	  9000
#define NEC_REPEATER_H_LEN_MAX	 10000
#define NEC_REPEATER_L_LEN_MIN	  2100
#define NEC_REPEATER_L_LEN_TYP	  2250
#define NEC_REPEATER_L_LEN_MAX	  2400

const int nec_data_h_len_min     = NEC_DATA_H_LEN_MIN / 100;
const int nec_data_h_len_max     = NEC_DATA_H_LEN_MAX / 100;
const int nec_data0_l_len_min    = NEC_DATA0_L_LEN_MIN / 100;
const int nec_data0_l_len_max    = NEC_DATA0_L_LEN_MAX / 100;
const int nec_data1_l_len_min    = NEC_DATA1_L_LEN_MIN / 100;
const int nec_data1_l_len_max    = NEC_DATA1_L_LEN_MAX / 100;
const int nec_repeater_l_len_min = NEC_REPEATER_L_LEN_MIN / 100;
const int nec_repeater_l_len_max = NEC_REPEATER_L_LEN_MAX / 100;

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
			if ((analyzer->dur >= nec_repeater_l_len_min) &&
			    (analyzer->dur <= nec_repeater_l_len_max))
				return DETECTED_PATTERN_REPEATER_L;
		}
	} else if (analyzer->state == ANALIZER_STATE_DATA) {
		if ((analyzer->dur >= nec_data0_l_len_min) &&
		    (analyzer->dur <= nec_data0_l_len_max)) {
			app_debug(REMOCON_FORMAT, 2, "%sdata0 at %d\n",
				  analyzer->msg_head, analyzer->src_idx);
			return DETECTED_PATTERN_DATA0;
		} else if ((analyzer->dur >= nec_data1_l_len_min) &&
			   (analyzer->dur <= nec_data1_l_len_max)) {
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
		if ((analyzer->dur >= nec_data_h_len_min) &&
		    (analyzer->dur <= nec_data_h_len_max)) {
			app_debug(REMOCON_FORMAT, 2,
				  "%srepeater detected at %d\n",
				  analyzer->msg_head, analyzer->src_idx);
			return DETECTED_PATTERN_REPEATER_H;
		}
	} else if (analyzer->state == ANALIZER_STATE_DATA) {
		if ((analyzer->dur >= nec_data_h_len_min) &&
		    (analyzer->dur <= nec_data_h_len_max))
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
	a->data_len = 4;
	a->leader_h_len_min  = NEC_LEADER_H_LEN_MIN / 100;
	a->leader_h_len_max  = NEC_LEADER_H_LEN_MAX / 100;
	a->leader_l_len_min  = NEC_LEADER_L_LEN_MIN / 100;
	a->leader_l_len_max  = NEC_LEADER_L_LEN_MAX / 100;
	a->trailer_l_len_min = NEC_TRAILER_L_LEN_MIN / 100;
	a->trailer_l_len_max = NEC_TRAILER_L_LEN_MAX / 100;
	a->cycle_len_min     = NEC_CYCLE_LEN_MIN / 100;
	a->cycle_len_max     = NEC_CYCLE_LEN_MAX / 100;
	a->check_dur0 = nec_check_dur0;
	a->check_dur1 = nec_check_dur1;
	a->check_unconditional = nec_check_unconditional;
	a->set_dest = set_dest;
}

#define nec_forge_leader(forger) \
	forge_pulse(forger, NEC_LEADER_H_LEN_TYP, NEC_LEADER_L_LEN_TYP)
#define nec_forge_data0(forger) \
	forge_pulse(forger, NEC_DATA_H_LEN_TYP, NEC_DATA0_L_LEN_TYP)
#define nec_forge_data1(forger) \
	forge_pulse(forger, NEC_DATA_H_LEN_TYP, NEC_DATA1_L_LEN_TYP)

int remocon_format_forge_nec(unsigned char *ptn, size_t sz,
			     unsigned short custom, unsigned char cmd)
{
	unsigned char custom_char[2] = {
		(unsigned char)(custom >> 8),
		(unsigned char)(custom & 0xff)
	};
	int idx;
	forger_t forger;
	unsigned long t_start;
	int i;

	forger_init(&forger, ptn, sz);

	t_start = forger.t;

	/* leader */
	nec_forge_leader(&forger);
	/* custom */
	for (idx = 0; idx < 16; idx++) {
		if (get_bit_in_ary(custom_char, idx))
			nec_forge_data1(&forger);
		else
			nec_forge_data0(&forger);
	}
	/* cmd */
	for (idx = 0; idx < 8; idx++) {
		if (get_bit_in_ary(&cmd, idx))
			nec_forge_data1(&forger);
		else
			nec_forge_data0(&forger);
	}
	cmd = ~cmd;
	for (idx = 0; idx < 8; idx++) {
		if (get_bit_in_ary(&cmd, idx))
			nec_forge_data1(&forger);
		else
			nec_forge_data0(&forger);
	}
	/* stop bit */
	forge_dur(&forger, 1, NEC_DATA_H_LEN_TYP);
	/* trailer */
	forge_until(&forger, 0, t_start + NEC_CYCLE_LEN_TYP);
	/* repeat */
	forge_pulse(&forger, NEC_REPEATER_H_LEN_TYP, NEC_REPEATER_L_LEN_TYP);
	forge_dur(&forger, 1, NEC_DATA_H_LEN_TYP);

	for (i = 0; i < sz; i++) {
		printf("%02x", ptn[i]);
	}
	putchar('\n');

	return 0;
}

/*
 * AEHA (Panasonic, SHARP etc.) format
 *
 * | leader | data | stop bit | trailer |
 * leader:  ------------------------------...............  3.4ms / 1.7ms
 * data0:   -----.....                                     0.425ms / 0.425ms
 * data1:   -----.................                         0.425ms / 1.275ms
 * trailer: ..............................                 20.0ms (> 8ms)
 *
 * data: 48 bit
 */
#define AEHA_LEADER_H_LEN_MIN	3100
#define AEHA_LEADER_H_LEN_TYP	3400
#define AEHA_LEADER_H_LEN_MAX	3700
#define AEHA_LEADER_L_LEN_MIN	1500
#define AEHA_LEADER_L_LEN_TYP	1700
#define AEHA_LEADER_L_LEN_MAX	1900
#define AEHA_DATA_H_LEN_MIN	 350
#define AEHA_DATA_H_LEN_TYP	 425
#define AEHA_DATA_H_LEN_MAX	 500
#define AEHA_DATA0_L_LEN_MIN	 350
#define AEHA_DATA0_L_LEN_TYP	 425
#define AEHA_DATA0_L_LEN_MAX	 500
#define AEHA_DATA1_L_LEN_MIN	1150
#define AEHA_DATA1_L_LEN_TYP	1275
#define AEHA_DATA1_L_LEN_MAX	1400
#define AEHA_TRAILER_L_LEN_MIN	8000
#define AEHA_TRAILER_L_LEN_TYP	20000	/* uknown. SHARP DVD */
#define AEHA_TRAILER_L_LEN_MAX	1000000	/* no condition */
#define AEHA_CYCLE_LEN_MIN	0	/* no condition */
/* #define AEHA_CYCLE_LEN_TYP */
#define AEHA_CYCLE_LEN_MAX	1000000	/* no condition */

const int aeha_data_h_len_min  = AEHA_DATA_H_LEN_MIN / 100;
const int aeha_data_h_len_max  = AEHA_DATA_H_LEN_MAX / 100;
const int aeha_data0_l_len_min = AEHA_DATA0_L_LEN_MIN / 100;
const int aeha_data0_l_len_max = AEHA_DATA0_L_LEN_MAX / 100;
const int aeha_data1_l_len_min = AEHA_DATA1_L_LEN_MIN / 100;
const int aeha_data1_l_len_max = AEHA_DATA1_L_LEN_MAX / 100;

static int aeha_check_dur0(const analyzer_t *analyzer)
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
		if ((analyzer->dur >= aeha_data0_l_len_min) &&
		    (analyzer->dur <= aeha_data0_l_len_max)) {
			app_debug(REMOCON_FORMAT, 2, "%sdata0 at %d\n",
				  analyzer->msg_head, analyzer->src_idx);
			return DETECTED_PATTERN_DATA0;
		} else if ((analyzer->dur >= aeha_data1_l_len_min) &&
			   (analyzer->dur <= aeha_data1_l_len_max)) {
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

static int aeha_check_dur1(const analyzer_t *analyzer)
{
	if (analyzer->state == ANALIZER_STATE_LEADER) {
		if ((analyzer->dur >= analyzer->leader_h_len_min) &&
		    (analyzer->dur <= analyzer->leader_h_len_max))
			return 0;
	} else if (analyzer->state == ANALIZER_STATE_DATA) {
		if ((analyzer->dur >= aeha_data_h_len_min) &&
		    (analyzer->dur <= aeha_data_h_len_max))
			return 0;
	}

	app_debug(REMOCON_FORMAT, 1,
		  "%sunmatched HIGH duration (%d) at %d (state = %d)\n",
		   analyzer->msg_head, analyzer->dur, analyzer->src_idx,
		   analyzer->state);
	return -1;
}

static int aeha_check_unconditional(const analyzer_t *analyzer)
{
	return 0;
}

static void aeha_analyzer_init(analyzer_t *a)
{
	a->msg_head = "[AEHA] ";
	a->data_bit_len_min = 48;	/* SHARP dvd, Panasonic STB */
	a->data_bit_len_max = 48;
	a->data_len = 6;
	a->leader_h_len_min  = AEHA_LEADER_H_LEN_MIN / 100;
	a->leader_h_len_max  = AEHA_LEADER_H_LEN_MAX / 100;
	a->leader_l_len_min  = AEHA_LEADER_L_LEN_MIN / 100;
	a->leader_l_len_max  = AEHA_LEADER_L_LEN_MAX / 100;
	a->trailer_l_len_min = AEHA_TRAILER_L_LEN_MIN / 100;
	a->trailer_l_len_max = AEHA_TRAILER_L_LEN_MAX / 100;
	a->cycle_len_min     = AEHA_CYCLE_LEN_MIN / 100;
	a->cycle_len_max     = AEHA_CYCLE_LEN_MAX / 100;
	a->check_dur0 = aeha_check_dur0;
	a->check_dur1 = aeha_check_dur1;
	a->check_unconditional = aeha_check_unconditional;
	a->set_dest = set_dest;
}

#define aeha_forge_leader(forger) \
	forge_pulse(forger, AEHA_LEADER_H_LEN_TYP, AEHA_LEADER_L_LEN_TYP)
#define aeha_forge_data0(forger) \
	forge_pulse(forger, AEHA_DATA_H_LEN_TYP, AEHA_DATA0_L_LEN_TYP)
#define aeha_forge_data1(forger) \
	forge_pulse(forger, AEHA_DATA_H_LEN_TYP, AEHA_DATA1_L_LEN_TYP)

int remocon_format_forge_aeha(unsigned char *ptn, size_t sz,
			      unsigned long custom, unsigned long cmd)
{
	unsigned char custom_char[2] = {
		(unsigned char)(custom & 0xff),
		(unsigned char)(custom >> 8)
	};
	unsigned char custom_parity = (((custom >> 12) & 0xf) ^
				       ((custom >>  8) & 0xf) ^
				       ((custom >>  4) & 0xf) ^
				       ( custom        & 0xf));
	unsigned char cmd_char[4] = {
		(unsigned char)( cmd        & 0xff),
		(unsigned char)((cmd >>  8) & 0xff),
		(unsigned char)((cmd >> 16) & 0xff),
		(unsigned char)((cmd >> 24) & 0x0f),
	};
	int idx;
	int repeat;
	forger_t forger;
	int i;

	forger_init(&forger, ptn, sz);

	for (repeat = 0; repeat < 2; repeat++) {
		/* leader */
		aeha_forge_leader(&forger);
		/* custom */
		for (idx = 0; idx < 16; idx++) {
			if (get_bit_in_ary(custom_char, idx))
				aeha_forge_data1(&forger);
			else
				aeha_forge_data0(&forger);
		}
		/* parity */
		for (idx = 0; idx < 4; idx++) {
			if (get_bit_in_ary(&custom_parity, idx))
				aeha_forge_data1(&forger);
			else
				aeha_forge_data0(&forger);
		}
		/* cmd */
		for (idx = 0; idx < 28; idx++) {
			if (get_bit_in_ary(cmd_char, idx))
				aeha_forge_data1(&forger);
			else
				aeha_forge_data0(&forger);
		}
		/* stop bit */
		forge_dur(&forger, 1, AEHA_DATA_H_LEN_TYP);
		/* trailer */
		forge_dur(&forger, 0, AEHA_TRAILER_L_LEN_TYP);
	}

	for (i = 0; i < sz; i++) {
		printf("%02x", ptn[i]);
	}
	putchar('\n');

	return 0;
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
#define SONY_LEADER_H_LEN_MIN	 2100
#define SONY_LEADER_H_LEN_TYP	 2400
#define SONY_LEADER_H_LEN_MAX	 2700
#define SONY_LEADER_L_LEN_MIN	  400
#define SONY_LEADER_L_LEN_TYP	  600
#define SONY_LEADER_L_LEN_MAX	  800
#define SONY_DATA0_H_LEN_MIN	  400
#define SONY_DATA0_H_LEN_TYP	  600
#define SONY_DATA0_H_LEN_MAX	  800
#define SONY_DATA1_H_LEN_MIN	 1000
#define SONY_DATA1_H_LEN_TYP	 1200
#define SONY_DATA1_H_LEN_MAX	 1400
#define SONY_DATA_L_LEN_MIN	  400
#define SONY_DATA_L_LEN_TYP	  600
#define SONY_DATA_L_LEN_MAX	  800
#define SONY_TRAILER_L_LEN_MIN	 6000	/* FIXME: arbitrary */
/* #define SONY_TRAILER_L_LEN_TYP */
#define SONY_TRAILER_L_LEN_MAX	50000	/* no condition. */
#define SONY_CYCLE_LEN_MIN	40000
#define SONY_CYCLE_LEN_TYP	45000
#define SONY_CYCLE_LEN_MAX	50000

const int sony_data0_h_len_min = SONY_DATA0_H_LEN_MIN / 100;
const int sony_data0_h_len_max = SONY_DATA0_H_LEN_MAX / 100;
const int sony_data1_h_len_min = SONY_DATA1_H_LEN_MIN / 100;
const int sony_data1_h_len_max = SONY_DATA1_H_LEN_MAX / 100;
const int sony_data_l_len_min  = SONY_DATA_L_LEN_MIN / 100;
const int sony_data_l_len_max  = SONY_DATA_L_LEN_MAX / 100;

static int sony_check_dur0(const analyzer_t *analyzer)
{
	if (analyzer->state == ANALIZER_STATE_LEADER) {
		/* didn't have enough 0 for leader */
	} else if (analyzer->state == ANALIZER_STATE_DATA) {
		if ((analyzer->dur >= sony_data_l_len_min) &&
		    (analyzer->dur <= sony_data_l_len_max))
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
		   (analyzer->dur == sony_data_l_len_min)) {
		if ((analyzer->dur_prev >= sony_data0_h_len_min) &&
		    (analyzer->dur_prev <= sony_data0_h_len_max)) {
			app_debug(REMOCON_FORMAT, 2, "%sdata0 at %d\n",
				  analyzer->msg_head, analyzer->src_idx);
			return DETECTED_PATTERN_DATA0;
		} else if ((analyzer->dur_prev >= sony_data1_h_len_min) &&
			   (analyzer->dur_prev <= sony_data1_h_len_max)) {
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
	a->leader_h_len_min  = SONY_LEADER_H_LEN_MIN / 100;
	a->leader_h_len_max  = SONY_LEADER_H_LEN_MAX / 100;
	a->leader_l_len_min  = SONY_LEADER_L_LEN_MIN / 100;
	a->leader_l_len_max  = SONY_LEADER_L_LEN_MAX / 100;
	a->trailer_l_len_min = SONY_TRAILER_L_LEN_MIN / 100;
	a->trailer_l_len_max = SONY_TRAILER_L_LEN_MAX / 100;
	a->cycle_len_min     = SONY_CYCLE_LEN_MIN / 100;
	a->cycle_len_max     = SONY_CYCLE_LEN_MAX / 100;
	a->check_dur0 = sony_check_dur0;
	a->check_dur1 = sony_check_dur1;
	a->check_unconditional = sony_check_unconditional;
	a->set_dest = set_dest;
};

#define sony_forge_leader(forger) \
	forge_pulse(forger, SONY_LEADER_H_LEN_TYP, SONY_LEADER_L_LEN_TYP)
#define sony_forge_data0(forger) \
	forge_pulse(forger, SONY_DATA0_H_LEN_TYP, SONY_DATA_L_LEN_TYP)
#define sony_forge_data1(forger) \
	forge_pulse(forger, SONY_DATA1_H_LEN_TYP, SONY_DATA_L_LEN_TYP)

int remocon_format_forge_sony(unsigned char *ptn, size_t sz,
			      unsigned long prod, unsigned long cmd)
{
	unsigned char cmd_concat[3];	/* 20 bit at max */
	int data_bit_len;
	int idx;
	int repeat;
	forger_t forger;
	int i;

	cmd_concat[0] = ((prod & 0x0001) << 7) | cmd;
	cmd_concat[1] =  (prod & 0x01fe) >> 1;
	cmd_concat[2] =  (prod & 0x1e00) >> 9;	/* 13 bit at max */

	data_bit_len = (prod & 0x1e00) ? 20 :
		       (prod & 0x00e0) ? 15 : 12;

	forger_init(&forger, ptn, sz);

	for (repeat = 0; repeat < 3; repeat++) {
		unsigned long t_start = forger.t;

		/* leader */
		sony_forge_leader(&forger);
		/* data */
		for (idx = 0; idx < data_bit_len; idx++) {
			if (get_bit_in_ary(cmd_concat, idx))
				sony_forge_data1(&forger);
			else
				sony_forge_data0(&forger);
		}
		/* trailer */
		forge_until(&forger, 0, t_start + SONY_CYCLE_LEN_TYP);
	}

	for (i = 0; i < sz; i++) {
		printf("%02x", ptn[i]);
	}
	putchar('\n');

	return 0;
}

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
#define KOIZ_DATA0_L_LEN_MIN	1500
#define KOIZ_DATA0_L_LEN_TYP	1670
#define KOIZ_DATA0_L_LEN_MAX	1850
#define KOIZ_DATA0_H_LEN_MIN	 700
#define KOIZ_DATA0_H_LEN_TYP	 830
#define KOIZ_DATA0_H_LEN_MAX	1000
#define KOIZ_DATA1_L_LEN_MIN	 700
#define KOIZ_DATA1_L_LEN_TYP	 830
#define KOIZ_DATA1_L_LEN_MAX	1000
#define KOIZ_DATA1_H_LEN_MIN	1500
#define KOIZ_DATA1_H_LEN_TYP	1670
#define KOIZ_DATA1_H_LEN_MAX	1850
#define KOIZ_MARKER_L_LEN_MIN	4500
#define KOIZ_MARKER_L_LEN_TYP	5000
#define KOIZ_MARKER_L_LEN_MAX	5500
#define KOIZ_MARKER_BIT_POS1	9
#define KOIZ_MARKER_BIT_POS2	12

const int koiz_data0_l_len_min  = KOIZ_DATA0_L_LEN_MIN / 100;
const int koiz_data0_l_len_max  = KOIZ_DATA0_L_LEN_MAX / 100;
const int koiz_data0_h_len_min  = KOIZ_DATA0_H_LEN_MIN / 100;
const int koiz_data0_h_len_max  = KOIZ_DATA0_H_LEN_MAX / 100;
const int koiz_data1_l_len_min  = KOIZ_DATA1_L_LEN_MIN / 100;
const int koiz_data1_l_len_max  = KOIZ_DATA1_L_LEN_MAX / 100;
const int koiz_data1_h_len_min  = KOIZ_DATA1_H_LEN_MIN / 100;
const int koiz_data1_h_len_max  = KOIZ_DATA1_H_LEN_MAX / 100;
const int koiz_marker_l_len_min = KOIZ_MARKER_L_LEN_MIN / 100;
const int koiz_marker_l_len_max = KOIZ_MARKER_L_LEN_MAX / 100;

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
		if ((analyzer->dur_prev >= koiz_data0_l_len_min) &&
		    (analyzer->dur_prev <= koiz_data0_l_len_max) &&
		    (analyzer->dur >= koiz_data0_h_len_min) &&
		    (analyzer->dur <= koiz_data0_h_len_max)) {
			app_debug(REMOCON_FORMAT, 2, "%sdata0 at %d\n",
				  analyzer->msg_head, analyzer->src_idx);
			return DETECTED_PATTERN_DATA0;
		} else if ((analyzer->dur_prev >= koiz_data1_l_len_min) &&
			   (analyzer->dur_prev <= koiz_data1_l_len_max) &&
			   (analyzer->dur >= koiz_data1_h_len_min) &&
			   (analyzer->dur <= koiz_data1_h_len_max)) {
			app_debug(REMOCON_FORMAT, 2, "%sdata1 at %d\n",
				  analyzer->msg_head, analyzer->src_idx);
			return DETECTED_PATTERN_DATA1;
		} else if ((analyzer->dur_prev >= koiz_marker_l_len_min) &&
			   (analyzer->dur_prev <= koiz_marker_l_len_max) &&
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
	a->leader_h_len_min = 700 / 100;	/* typ = 8.3 */
	a->leader_h_len_max = 1000 / 100;
	a->leader_l_len_min = 700 / 100;	/* typ = 8.3 or 16.7 */
	a->leader_l_len_max = 1900 / 100;

	a->trailer_l_len_min = 11900 / 100;	/* typ = 132 */
	a->trailer_l_len_max = 14500 / 100;
	a->cycle_len_min = 0 / 100;		/* no condition */
	a->cycle_len_max = 1000000 / 100;	/* no condition */
	a->check_dur0 = koiz_check_dur0;
	a->check_dur1 = koiz_check_dur1;
	a->check_unconditional = koiz_check_unconditional;
	a->set_dest = koiz_set_dest;
}

/*
 * generic analyzer func
 */
static int analyze(analyzer_t *analyzer, unsigned char *dst,
		   const unsigned char *ptn, size_t sz)
{
	unsigned char dst_tmp[DATA_LEN_MAX] = { 0 };
	size_t sz_bit = sz * 8;
	int r;

	analyzer_init(analyzer);
	for (analyzer->src_idx = 0;
	     analyzer->src_idx < sz_bit;
	     analyzer->src_idx++) {
		char this_bit = get_bit_in_ary(ptn, analyzer->src_idx);

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
			   const unsigned char *ptn, size_t sz)
{
	unsigned char buf[DATA_LEN_MAX];
	analyzer_t analyzer;

	aeha_analyzer_init(&analyzer);
	if (analyze(&analyzer, buf, ptn, sz) >= 0) {
		unsigned short custom = ((unsigned short)buf[1] << 8) | buf[0];
		unsigned char parity = buf[2] & 0xf;
		unsigned long cmd = ( (unsigned long)buf[5]         << 20) |
				    ( (unsigned long)buf[4]         << 12) |
				    ( (unsigned long)buf[3]         <<  4) |
				    (((unsigned long)buf[2] & 0xf0) >>  4);
		if ((((buf[0] >> 4) & 0xf) ^
		      (buf[0] & 0xf) ^
		     ((buf[1] >> 4) & 0xf) ^
		      (buf[1] & 0xf)) != parity) {
			app_debug(REMOCON_FORMAT, 1,
				  "AEHA pattern detected, but"
				  " parity is inconsistent.\n"
				  "%04x %01x %07lx",
				  custom, parity, cmd);
		}
		strcpy(fmt_tag, "AEHA");
		sprintf(dst, "custom=%04x cmd=%07lx", custom, cmd);
		return 0;
	}

	nec_analyzer_init(&analyzer);
	if (analyze(&analyzer, buf, ptn, sz) >= 0) {
		unsigned short custom = ((unsigned short)buf[0] << 8) | buf[1];
		unsigned char cmd = buf[2];
		/* NOTE: custom' is not always ~custom !! */
		if (buf[2] != (unsigned char)~buf[3]) {
			app_debug(REMOCON_FORMAT, 1,
				  "NEC pattern detected, but"
				  " data is inconsistent.\n"
				  "%02x%02x %02x%02x",
				  buf[0], buf[1], buf[2], buf[3]);
			return -1;
		}
		strcpy(fmt_tag, "NEC");
		sprintf(dst, "custom=%04x cmd=%02x", custom, cmd);
		return 0;
	}

	sony_analyzer_init(&analyzer);
	if (analyze(&analyzer, buf, ptn, sz) >= 0) {
		unsigned char cmd;
		unsigned short prod;

		cmd = buf[0] & 0x7f;
		prod = ((unsigned short)buf[2] << 9) |
		       ((unsigned short)buf[1] << 1) |
		       (buf[0] >> 7);
		strcpy(fmt_tag, "SONY");
		sprintf(dst, "prod=%04x cmd=%02x", prod, cmd);
		return 0;
	}

	koiz_analyzer_init(&analyzer);
	if (analyze(&analyzer, buf, ptn, sz) >= 0) {
		unsigned char id;
		unsigned short cmd;

		id = (buf[1] >> 1) & 0x7;
		cmd = (((unsigned short)buf[1] << 8) | buf[0]) & 0x1ff;
		strcpy(fmt_tag, "KOIZ");
		sprintf(dst, "id=%02x cmd=%04x", id, cmd);
		return 0;
	}

	return -1;
}
